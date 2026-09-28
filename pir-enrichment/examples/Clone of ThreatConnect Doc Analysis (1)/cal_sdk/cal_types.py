# -*- coding: utf-8 -*-
"""Various types for handling CAL responses"""
# standard library
from typing import Dict, List


class CALDetail:
    """A detail object from a CAL details API response."""

    def __init__(self, raw_dict=None):
        """Representation of CAL Details API Detail object.

        Args:
            raw_dict: the details array from the API response, parsed.
        """
        if raw_dict is None:
            raw_dict = {}
        self.json = raw_dict
    
    @property
    def description(self):
        """Return the description field."""
        return self.json.get('description')
    
    @property
    def display_name(self):
        """Return the display_name field."""
        return self.json.get('display_name')
    
    @property
    def group(self):
        """Return the group field."""
        return self.json.get('group')
    
    @property
    def name(self):
        """Return the name field

        Returns:
            the "name" field.
        """
        return self.json.get('name')

    @property
    def value(self):
        """Return the value field

        Returns:
            the "value" field.
        """
        return self.json.get('value')


class CALDetailsResponse:
    """Response from the CAL details API: details for a single indicator."""

    def __init__(self, raw_dict: Dict[str, int]):
        """Representation of a response from the CAL details API.

        Args:
            raw_dict: the raw json response from CAL, parsed into a dict.
        """
        self._json = raw_dict
        self._parsed_details = None

    @property
    def unique_id(self):
        """Return the unique ID field

        Returns:
            the "uniqueId" field, which is the indicator value.
        """
        return self._json.get('uniqueId')

    @property
    def score(self):
        """Return the score field

        Returns:
            the "score" field
        """
        return self._json.get('score')

    @property
    def indicator_status(self):
        """Return the indicatorStatus field

        Returns:
            the "indicatorStatus" field.
        """
        return self._json.get('indicatorStatus')

    @property
    def good(self):
        """Returns the good field.

        Returns:
            the "good" field.
        """
        return self._json.get('good')

    @property
    def details(self) -> List[CALDetail]:
        """Return a list of details in this CAL response.

        Returns:
            A list of the details in this response, wrapped in CALDetail objects.
        """
        if self._parsed_details is None:
            self._parsed_details = list([CALDetail(d) for d in self._json.get('details', [])])

        return self._parsed_details
