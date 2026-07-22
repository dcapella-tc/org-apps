"""Map OTX targeted_countries strings to ThreatConnect Target Country allowlist values."""

from __future__ import annotations

from typing import Any

# ThreatConnect Target Country allowlist (exact strings; semicolon-delimited source).
_TC_TARGET_COUNTRY_LIST = (
    'United States;Afghanistan;Åland Islands;Albania;Algeria;American Samoa;Andorra;'
    'Angola;Anguilla;Antarctica;Antigua And Barbuda;Argentina;Armenia;Aruba;Australia;'
    'Austria;Azerbaijan;Bahamas;Bahrain;Bangladesh;Barbados;Belarus;Belgium;Belize;Benin;'
    'Bermuda;Bhutan;Bolivia;Bonaire;Bosnia And Herzegovina;Botswana;Bouvet Island;Brazil;'
    'British Indian Ocean Territory;Brunei Darussalam;Bulgaria;Burkina Faso;Burundi;'
    'Cambodia;Cameroon;Canada;Cape Verde;Cayman Islands;Central African Republic;Chad;'
    'Chile;China;Christmas Island;Cocos (Keeling) Islands;Colombia;Comoros;Congo;'
    'Congo, The Democratic Republic Of The;Cook Islands;Costa Rica;Cote D\'ivoire;'
    'Country of Curaçao;Croatia;Cuba;Cyprus;Czech Republic;Denmark;Djibouti;Dominica;'
    'Dominican Republic;Ecuador;Egypt;El Salvador;Equatorial Guinea;Eritrea;Estonia;'
    'Ethiopia;Falkland Islands (Malvinas);Faroe Islands;Fiji;Finland;France;French Guiana;'
    'French Polynesia;French Southern Territories;Gabon;Gambia;Georgia;Germany;Ghana;'
    'Gibraltar;Global;Greece;Greenland;Grenada;Guadeloupe;Guam;Guatemala;Guernsey;Guinea;'
    'Guinea-bis;Guinea-bissau;Guyana;Haiti;Heard Island And Mcdonald Islands;'
    'Holy See (Vatican City State);Honduras;Hong Kong;Hungary;Iceland;India;Indonesia;'
    'Iran, Islamic Republic Of;Iraq;Ireland;Isle Of Man;Israel;Italy;Jamaica;Japan;Jersey;'
    'Jordan;Kazakhstan;Kenya;Kiribati;Korea, Democratic People\'s Republic Of;'
    'Korea, Republic Of;Kuwait;Kyrgyzstan;Lao People\'s Democratic Republic;Latvia;'
    'Lebanon;Lesotho;Liberia;Libyan Arab Jamahiriya;Liechtenstein;Lithuania;Luxembourg;'
    'Macao;Macedonia, The Former Yugoslav Republic Of;Madagascar;Malawi;Malaysia;Maldives;'
    'Mali;Malta;Marshall Islands;Martinique;Mauritania;Mauritius;Mayotte;Mexico;'
    'Micronesia, Federated States Of;Moldova, Republic Of;Monaco;Mongolia;Montenegro;'
    'Montserrat;Morocco;Mozambique;Myanmar;Namibia;Nauru;Nepal;Netherlands;'
    'Netherlands Antilles;New Caledonia;New Zealand;Nicaragua;Niger;Nigeria;Niue;'
    'Norfolk Island;Northern Mariana Islands;Norway;Oman;Pakistan;Palau;'
    'Palestinian Territory, Occupied;Panama;Papua New Guinea;Paraguay;Peru;Philippines;'
    'Pitcairn;Poland;Portugal;Puerto Rico;Qatar;Reunion;Romania;Russian Federation;'
    'Rwanda;Saint Barthélemy;Saint Helena;Saint Kitts And Nevis;Saint Lucia;Saint Martin;'
    'Saint Pierre And Miquelon;Saint Vincent And The Grenadines;Samoa;San Marino;'
    'Sao Tome And Principe;Saudi Arabia;Senegal;Serbia;Seychelles;Sierra Leone;Singapore;'
    'Slovakia;Slovenia;Solomon Islands;Somalia;South Africa;'
    'South Georgia And The South Sandwich Islands;South Sudan;Spain;Sri Lanka;Sudan;'
    'Sudan, Republic of;Suriname;Svalbard And Jan Mayen;Swaziland;Sweden;Switzerland;'
    'Syrian Arab Republic;Taiwan, Province Of China;Tajikistan;'
    'Tanzania, United Republic Of;Thailand;Timor-leste;Togo;Tokelau;Tonga;'
    'Trinidad And Tobago;Tunisia;Turkey;Turkmenistan;Turks And Caicos Islands;Tuvalu;'
    'Uganda;Ukraine;United Arab Emirates;United Kingdom;'
    'United States Minor Outlying Islands;Uruguay;Uzbekistan;Vanuatu;Venezuela;Viet Nam;'
    'Virgin Islands, British;Virgin Islands, U.S.;Wallis And Futuna;Western Sahara;Yemen;'
    'Zambia;Zimbabwe'
)

TC_TARGET_COUNTRIES: tuple[str, ...] = tuple(
    part.strip() for part in _TC_TARGET_COUNTRY_LIST.split(';') if part.strip()
)

_EXACT_BY_CASEFOLD: dict[str, str] = {name.casefold(): name for name in TC_TARGET_COUNTRIES}

# OTX / common short names → TC allowlist canonical value (casefold keys).
_ALIASES: dict[str, str] = {
    'taiwan': 'Taiwan, Province Of China',
    'united states of america': 'United States',
    'usa': 'United States',
    'us': 'United States',
    'u.s.': 'United States',
    'u.s.a.': 'United States',
    'america': 'United States',
    'russia': 'Russian Federation',
    'russian federation': 'Russian Federation',
    'south korea': 'Korea, Republic Of',
    'korea': 'Korea, Republic Of',
    'republic of korea': 'Korea, Republic Of',
    'north korea': "Korea, Democratic People's Republic Of",
    'dprk': "Korea, Democratic People's Republic Of",
    'vietnam': 'Viet Nam',
    'viet nam': 'Viet Nam',
    'iran': 'Iran, Islamic Republic Of',
    'syria': 'Syrian Arab Republic',
    'tanzania': 'Tanzania, United Republic Of',
    'laos': "Lao People's Democratic Republic",
    'moldova': 'Moldova, Republic Of',
    'venezuela': 'Venezuela',
    'bolivia': 'Bolivia',
    'brunei': 'Brunei Darussalam',
    'czech': 'Czech Republic',
    'czechia': 'Czech Republic',
    'ivory coast': "Cote D'ivoire",
    "cote d'ivoire": "Cote D'ivoire",
    'uk': 'United Kingdom',
    'great britain': 'United Kingdom',
    'britain': 'United Kingdom',
    'uae': 'United Arab Emirates',
    'palestine': 'Palestinian Territory, Occupied',
    'vatican': 'Holy See (Vatican City State)',
    'vatican city': 'Holy See (Vatican City State)',
    'macedonia': 'Macedonia, The Former Yugoslav Republic Of',
    'north macedonia': 'Macedonia, The Former Yugoslav Republic Of',
    'democratic republic of the congo': 'Congo, The Democratic Republic Of The',
    'drc': 'Congo, The Democratic Republic Of The',
    'congo-kinshasa': 'Congo, The Democratic Republic Of The',
    'republic of the congo': 'Congo',
    'congo-brazzaville': 'Congo',
    'swaziland': 'Swaziland',
    'eswatini': 'Swaziland',
    'myanmar': 'Myanmar',
    'burma': 'Myanmar',
    'east timor': 'Timor-leste',
    'timor leste': 'Timor-leste',
    'curacao': 'Country of Curaçao',
    'curaçao': 'Country of Curaçao',
    'hong kong': 'Hong Kong',
    'macau': 'Macao',
    'macao': 'Macao',
}


def map_target_country(raw: str) -> str | None:
    """Return the TC allowlist country string, or None if unmapped."""
    text = str(raw).strip()
    if not text:
        return None
    key = text.casefold()
    if key in _EXACT_BY_CASEFOLD:
        return _EXACT_BY_CASEFOLD[key]
    alias = _ALIASES.get(key)
    if alias is not None:
        return alias
    return None


def resolve_targeted_countries(
    pulse: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Split pulse countries into ``(mapped_tc_values, unmatched_otx_values)``.

    Order preserved; empty strings skipped. Mapped values are deduped by
    casefold of the TC canonical string. Unmatched keep OTX raw text (deduped
    by casefold).
    """
    mapped: list[str] = []
    unmatched: list[str] = []
    seen_mapped: set[str] = set()
    seen_unmatched: set[str] = set()

    values = pulse.get('targeted_countries') or []
    if not isinstance(values, list):
        return mapped, unmatched

    for item in values:
        if item is None:
            continue
        raw = str(item).strip()
        if not raw:
            continue
        tc = map_target_country(raw)
        if tc is not None:
            key = tc.casefold()
            if key not in seen_mapped:
                seen_mapped.add(key)
                mapped.append(tc)
        else:
            key = raw.casefold()
            if key not in seen_unmatched:
                seen_unmatched.add(key)
                unmatched.append(raw)

    return mapped, unmatched
