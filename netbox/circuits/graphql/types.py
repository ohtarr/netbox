import strawberry

from circuits import filtersets, models
from dcim.graphql.mixins import CabledObjectMixin
from extras.graphql.mixins import CustomFieldsMixin, TagsMixin, ContactsMixin
from netbox.graphql.types import ObjectType, OrganizationalObjectType, NetBoxObjectType
from .filters import *
from typing import List

__all__ = (
    'CircuitTerminationType',
    'CircuitType',
    'CircuitTypeType',
    'ProviderType',
    'ProviderAccountType',
    'ProviderNetworkType',
)


@strawberry.django.type(
    models.Provider,
    fields='__all__',
    filters=ProviderFilter
)
class ProviderType(NetBoxObjectType, ContactsMixin):
    pass


@strawberry.django.type(
    models.ProviderAccount,
    fields='__all__',
    filters=ProviderAccountFilter
)
class ProviderAccountType(NetBoxObjectType):
    pass


@strawberry.django.type(
    models.ProviderNetwork,
    fields='__all__',
    filters=ProviderNetworkFilter
)
class ProviderNetworkType(NetBoxObjectType):
    pass


@strawberry.django.type(
    models.CircuitTermination,
    fields='__all__',
    filters=CircuitTerminationFilter
)
class CircuitTerminationType(CustomFieldsMixin, TagsMixin, CabledObjectMixin, ObjectType):
    pass


@strawberry.django.type(
    models.Circuit,
    fields='__all__',
    filters=CircuitFilter
)
class CircuitType(NetBoxObjectType, ContactsMixin):
    provider: ProviderType


@strawberry.django.type(
    models.CircuitType,
    fields='__all__',
    filters=CircuitTypeFilter
)
class CircuitTypeType(OrganizationalObjectType):
    pass
