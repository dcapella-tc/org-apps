"""App Inputs"""

from datetime import datetime, timedelta, timezone

from pydantic import Field
from tcex.input.field_type import String
from tcex.input.input import Input
from tcex.input.model.app_organization_model import AppOrganizationModel


def _default_last_run_str() -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=7)
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


class AppBaseModel(AppOrganizationModel):
    """Base model for the App containing any common inputs."""

    tc_owner: String
    emails: String
    max_results: String = String("4")
    last_run: String = Field(default_factory=_default_last_run_str)


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize class properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App models to inputs. Validation will run at the same time."""
        self.inputs.add_model(AppBaseModel)
