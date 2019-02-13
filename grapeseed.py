# coding: utf-8
import re
import html
import inflection
from collections import OrderedDict


def _to_snake(text_to_convert):
    return inflection.underscore(text_to_convert.strip().replace(" ", "_"))


def _convert_content_to_dict(lines):
    return_value = dict()

    for line in lines:
        key, value = line.split(':', 1)
        snake_key = _to_snake(key)
        return_value[snake_key] = value.strip()

    return return_value


def convert_notification_mail(plaintext_body):
    return_value = OrderedDict()
    return_value['antivirus_results'] = dict()

    _plaintext = plaintext_body.replace('\x20\x20\x0d\x0a', '\x20')

    matches = []
    for line in _plaintext.splitlines():
        if re.match("^[0-9A-F][0-9A-F] .+?$", line):
            _plaintext = _plaintext.replace(line, '')
            matches.append(html.unescape(line))

    result = re.match("(?P<basic>.+)\r?\n(\r?\n|\.\.\.\r?\n)\r?\n(?P<additional>.+)", _plaintext, re.DOTALL)

    matching_group = result.groupdict()
    basic_part = matching_group['basic'].strip()
    additional_part = matching_group['additional'].strip()

    lines = []
    firstcountry_seen = False

    for idx, line in enumerate(basic_part.splitlines()):
        if line.startswith('https://www.virustotal.com/') or ((not firstcountry_seen) and (":" not in line)):
            lines[-1] = lines[-1].strip() + ' ' + line.strip()
            continue

        if firstcountry_seen:
            results = re.search("^(?P<vendor>.+?)\s+(?P<name>.+?)$", line)

            if results:
                group = results.groupdict()
                return_value['antivirus_results'][group['vendor']] = group['name']

            continue

        if line.startswith("First country"):
            firstcountry_seen = True

        lines.append(line)

    xx = _convert_content_to_dict(lines)
    return_value = {**xx, **return_value}
    return_value['matches'] = '\r\n'.join(matches)

    xxx = re.split('\r\n\r\n', additional_part)

    for xx in xxx:
        if not xx:
            continue

        splitted = re.split('\r?\n=+?\r?\n', xx)
        title, content = splitted

        additional_lines = []
        for idx, line in enumerate(content.splitlines()):
            additional_lines.append(line)

        value = _convert_content_to_dict(additional_lines)

        return_value[_to_snake(title)] = value

    return return_value
