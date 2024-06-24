from storages.backends.azure_storage import AzureStorage
import os

class AzureMediaStorage(AzureStorage):
    account_name = os.getenv("NBX_STORAGE_NAME")
    account_key = os.getenv("NBX_STORAGE_KEY")
    azure_container = os.getenv("NBX_STORAGE_MEDIA_CONTAINER")
    expiration_secs = int(os.getenv("NBX_STORAGE_MEDIA_CONTAINER_EXPIRATION"))

class AzureStaticStorage(AzureStorage):
    account_name = os.getenv("NBX_STORAGE_NAME")
    account_key = os.getenv("NBX_STORAGE_KEY")
    azure_container = os.getenv("NBX_STORAGE_STATIC_CONTAINER")
    expiration_secs = None