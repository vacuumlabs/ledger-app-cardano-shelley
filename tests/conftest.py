import pytest
from ragger.conftest import configuration
from ragger.backend import BackendInterface

from application_client.command_sender import CommandSender

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of
#  ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values


#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


##########################
# CONFIGURATION OVERRIDE #
##########################

@pytest.fixture(scope=configuration.OPTIONAL.BACKEND_SCOPE)
def appFlags(backend: BackendInterface) -> dict:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # Send the APDU
    version = client.get_version()
    app_flags = {
        "isDebug": bool(version[3] & 0x01),
        "isAppXS": bool(version[3] & 0x04)
    }

    return app_flags
