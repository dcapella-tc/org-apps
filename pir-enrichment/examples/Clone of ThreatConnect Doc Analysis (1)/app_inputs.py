"""App Inputs"""

# pyright: reportGeneralTypeIssues=false

# third-party
from pydantic import BaseModel, Field, validator
from tcex.input.field_type import Choice, Sensitive, TCEntity, binary, entity_input, string
from tcex.input.input import Input
from tcex.input.model.app_playbook_model import AppPlaybookModel


class AppBaseModel(AppPlaybookModel):
    """Base model for the App containing any common inputs."""

    # pbd: Binary|String|TCEntity, vv: ${TEXT}
    document: binary(allow_empty=False) | string(allow_empty=False) | TCEntity
    fail_on_error: bool = False
    # vv: Analyze Document
    tc_action: Choice

    # add entity_input validator for supported types
    _entity_input = validator('document', allow_reuse=True)(entity_input(only_field='value'))

    features: list
    additional_features: str | None = None

    @validator('additional_features', pre=True, always=True)
    def _normalize_additional_features(cls, value):  # pylint: disable=no-self-argument
        """Treat literal 'None' (case-insensitive) as absence."""

        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() == 'none':
            return None
        return value


class AnalyzeDocumentModel(AppBaseModel):
    """Action Model"""


class CalSettingModel(AppBaseModel):
    """CAL Settings Model

    Feature: CALSettings

    Supported for the following runtimeLevel:
    * ApiService
    * Playbook
    * WebhookTriggerService
    * TriggerService
    """

    #
    # ThreatConnect Provided Inputs
    #

    tc_cal_host: str = Field(
        ...,
        description='The hostname for CAL.',
        inclusion_reason='feature (CALSettings)',
    )
    tc_cal_token: str = Field(
        ...,
        description='The token for CAL.',
        inclusion_reason='feature (CALSettings)',
    )
    tc_cal_timestamp: int = Field(
        ...,
        description='The expiration timestamp in epoch for tc_cal_token.',
        inclusion_reason='feature (CALSettings)',
    )


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize instance properties."""
        self.inputs = inputs

    def action_model_map(self, tc_action: str) -> type[BaseModel]:
        """Return action model map."""
        _action_model_map = {
            'analyze_document': AnalyzeDocumentModel,
        }
        tc_action_key = tc_action.lower().replace(' ', '_')
        return _action_model_map.get(tc_action_key)

    def get_model(self, tc_action: str | None = None) -> type[BaseModel]:
        """Return the model based on the current action."""
        tc_action = tc_action or self.inputs.model_unresolved.tc_action  # type: ignore
        if tc_action is None:
            raise RuntimeError('No action (tc_action) found in inputs.')

        action_model = self.action_model_map(tc_action.lower())
        if action_model is None:
            # pylint: disable=broad-exception-raised
            raise RuntimeError(
                'No model found for action: '
                f'{self.inputs.model_unresolved.tc_action}'  # type: ignore
            )

        return action_model

    def update_inputs(self):
        """Add custom App model to inputs.

        Input will be validate when the model is added an any exceptions will
        cause the App to exit with a status code of 1.
        """
        self.inputs.add_model(self.get_model())
