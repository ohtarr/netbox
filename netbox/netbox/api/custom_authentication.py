import logging

from django.conf import settings
from django.utils import timezone
from rest_framework import authentication, HTTP_HEADER_ENCODING, exceptions
from rest_framework.permissions import BasePermission, DjangoObjectPermissions, SAFE_METHODS

from netbox.config import get_config
from users.models import Token
from utilities.request import get_client_ip

#from netbox.api import custom_authentication1


def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.
    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get("HTTP_" + settings.API_AUTH_HEADER, b'')
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth

class CustomTokenAuthentication(authentication.TokenAuthentication):
    """
    Simple token based authentication.
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:
        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    keyword = 'Token'
    model = None

    def get_model(self):
        if self.model is not None:
            return self.model
        from rest_framework.authtoken.models import Token
        return Token

    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)

    def authenticate_header(self, request):
        return self.keyword

class TokenAuthentication(CustomTokenAuthentication):
#class TokenAuthentication(custom_authentication1.TokenAuthentication):
    """
    A custom authentication scheme which enforces Token expiration times and source IP restrictions.
    """
    model = Token

    def authenticate(self, request):
        result = super().authenticate(request)

        if result:
            token = result[1]

            # Enforce source IP restrictions (if any) set on the token
            if token.allowed_ips:
                client_ip = get_client_ip(request)
                if client_ip is None:
                    raise exceptions.AuthenticationFailed(
                        "Client IP address could not be determined for validation. Check that the HTTP server is "
                        "correctly configured to pass the required header(s)."
                    )
                if not token.validate_client_ip(client_ip):
                    raise exceptions.AuthenticationFailed(
                        f"Source IP {client_ip} is not permitted to authenticate using this token."
                    )

        return result

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.prefetch_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid token")

        # Update last used, but only once per minute at most. This reduces write load on the database
        if not token.last_used or (timezone.now() - token.last_used).total_seconds() > 60:
            # If maintenance mode is enabled, assume the database is read-only, and disable updating the token's
            # last_used time upon authentication.
            if get_config().MAINTENANCE_MODE:
                logger = logging.getLogger('netbox.auth.login')
                logger.debug("Maintenance mode enabled: Disabling update of token's last used timestamp")
            else:
                Token.objects.filter(pk=token.pk).update(last_used=timezone.now())

        # Enforce the Token's expiration time, if one has been set.
        if token.is_expired:
            raise exceptions.AuthenticationFailed("Token expired")

        user = token.user
        # When LDAP authentication is active try to load user data from LDAP directory
        if settings.REMOTE_AUTH_BACKEND == 'netbox.authentication.LDAPBackend':
            from netbox.authentication import LDAPBackend
            ldap_backend = LDAPBackend()

            # Load from LDAP if FIND_GROUP_PERMS is active
            # Always query LDAP when user is not active, otherwise it is never activated again
            if ldap_backend.settings.FIND_GROUP_PERMS or not token.user.is_active:
                ldap_user = ldap_backend.populate_user(token.user.username)
                # If the user is found in the LDAP directory use it, if not fallback to the local user
                if ldap_user:
                    user = ldap_user

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User inactive")

        return user, token


class TokenPermissions(DjangoObjectPermissions):
    """
    Custom permissions handler which extends the built-in DjangoModelPermissions to validate a Token's write ability
    for unsafe requests (POST/PUT/PATCH/DELETE).
    """
    # Override the stock perm_map to enforce view permissions
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': ['%(app_label)s.view_%(model_name)s'],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    def __init__(self):

        # LOGIN_REQUIRED determines whether read-only access is provided to anonymous users.
        self.authenticated_users_only = settings.LOGIN_REQUIRED

        super().__init__()

    def _verify_write_permission(self, request):

        # If token authentication is in use, verify that the token allows write operations (for unsafe methods).
        if request.method in SAFE_METHODS or request.auth.write_enabled:
            return True

    def has_permission(self, request, view):

        # Enforce Token write ability
        if isinstance(request.auth, Token) and not self._verify_write_permission(request):
            return False

        return super().has_permission(request, view)

    def has_object_permission(self, request, view, obj):

        # Enforce Token write ability
        if isinstance(request.auth, Token) and not self._verify_write_permission(request):
            return False

        return super().has_object_permission(request, view, obj)


class IsAuthenticatedOrLoginNotRequired(BasePermission):
    """
    Returns True if the user is authenticated or LOGIN_REQUIRED is False.
    """
    def has_permission(self, request, view):
        if not settings.LOGIN_REQUIRED:
            return True
        return request.user.is_authenticated
