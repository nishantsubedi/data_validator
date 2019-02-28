library data_validator;

import 'dart:convert';

RegExp _alpha = new RegExp(r'^[a-zA-Z]+$');
RegExp _alphanumeric = new RegExp(r'^[a-zA-Z0-9]+$');
RegExp _numeric = new RegExp(r'^-?[0-9]+$');
RegExp _int = new RegExp(r'^(?:-?(?:0|[1-9][0-9]*))$');
RegExp _float =
    new RegExp(r'^(?:-?(?:[0-9]+))?(?:\.[0-9]*)?(?:[eE][\+\-]?(?:[0-9]+))?$');
RegExp _hexadecimal = new RegExp(r'^[0-9a-fA-F]+$');
RegExp _hexcolor = new RegExp(r'^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$');
RegExp _surrogatePairsRegExp = new RegExp(r'[\uD800-\uDBFF][\uDC00-\uDFFF]');
Map _uuid = {
  '3': new RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-3[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$'),
  '4': new RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$'),
  '5': new RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$'),
  'all': new RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$')
};
RegExp _base64 = new RegExp(
    r'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$');
RegExp _multibyte = new RegExp(r'[^\x00-\x7F]');
RegExp _ascii = new RegExp(r'^[\x00-\x7F]+$');
RegExp _fullWidth = new RegExp(
    r'[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]');
RegExp _halfWidth = new RegExp(
    r'[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]');
RegExp _creditCard = new RegExp(
    r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$');

RegExp _isbn10Maybe = new RegExp(r'^(?:[0-9]{9}X|[0-9]{10})$');
RegExp _isbn13Maybe = new RegExp(r'^(?:[0-9]{13})$');
const Map _default_normalize_email_options = {'lowercase': true};

/// Validates different data types like email, password, date, ip address e.t.c.
class DataValidator {
  /// Returns true if email is valid
  static bool isEmail(String email) {
    return RegExp(
            r'^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$')
        .hasMatch(email);
  }

  /// Returns true if Phone Number is valid
  static bool isPhoneNumber(String number) {
    return RegExp(
            r"^[01]?[- .]?(\([2-9]\d{2}\)|[2-9]\d{2})[- .]?\d{3}[- .]?\d{4}$")
        .hasMatch(number);
  }

  /// check if the string matches the comparison
  static bool equals(String str, comparison) {
    return str == comparison.toString();
  }

  /// check if the string contains the seed
  static bool stringContains(String str, seed) {
    return str.indexOf(seed.toString()) >= 0;
  }

  /// check if string matches the pattern.
  static bool matches(String str, pattern) {
    RegExp re = new RegExp(pattern);
    return re.hasMatch(str);
  }

  /// check if the string is an IP (version 4 or 6)
  ///
  /// `version` is a String or an `int`.
  static bool isIP(String str, [version]) {
    version = version.toString();
    if (version == 'null') {
      return isIP(str, 4) || isIP(str, 6);
    } else if (version == '4') {
      if (!RegExp(r"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b")
          .hasMatch(str)) {
        return false;
      }
      var parts = str.split('.');
      parts.sort((a, b) => int.parse(a) - int.parse(b));
      return int.parse(parts[3]) <= 255;
    }
    return version == '6' &&
        RegExp(r'^::|^::1|^([a-fA-F0-9]{1,4}::?){1,7}([a-fA-F0-9]{1,4})$')
            .hasMatch(str);
  }

  /// check if the string is a fully qualified domain name (e.g. domain.com).
  ///
  /// `options` is a `Map` which defaults to `{ 'require_tld': true, 'allow_underscores': false }`.
  static bool isFQDN(str, [options]) {
    const Map default_fqdn_options = {
      'require_tld': true,
      'allow_underscores': false
    };

    options = _merge(options, default_fqdn_options);
    List parts = str.split('.');
    if (options['require_tld']) {
      var tld = parts.removeLast();
      if (parts.length == 0 || !new RegExp(r'^[a-z]{2,}$').hasMatch(tld)) {
        return false;
      }
    }

    for (var part, i = 0; i < parts.length; i++) {
      part = parts[i];
      if (options['allow_underscores']) {
        if (part.indexOf('__') >= 0) {
          return false;
        }
      }
      if (!new RegExp(r'^[a-z\\u00a1-\\uffff0-9-]+$').hasMatch(part)) {
        return false;
      }
      if (part[0] == '-' ||
          part[part.length - 1] == '-' ||
          part.indexOf('---') >= 0) {
        return false;
      }
    }
    return true;
  }

  /// check if the string contains only letters (a-zA-Z).
  static bool isAlpha(String str) {
    return _alpha.hasMatch(str);
  }

  /// check if the string contains only numbers
  static bool isNumeric(String str) {
    return _numeric.hasMatch(str);
  }

  /// check if the string contains only letters and numbers
  static bool isAlphanumeric(String str) {
    return _alphanumeric.hasMatch(str);
  }

  /// check if a string is base64 encoded
  static bool isBase64(String str) {
    return _base64.hasMatch(str);
  }

  /// check if the string is an integer
  static bool isInt(String str) {
    return _int.hasMatch(str);
  }

  /// check if the string is a float
  static bool isFloat(String str) {
    return _float.hasMatch(str);
  }

  /// check if the string is a hexadecimal number
  static bool isHexadecimal(String str) {
    return _hexadecimal.hasMatch(str);
  }

  /// check if the string is a hexadecimal color
  static bool isHexColor(String str) {
    return _hexcolor.hasMatch(str);
  }

  /// check if the string is lowercase
  static bool isLowercase(String str) {
    return str == str.toLowerCase();
  }

  /// check if the string is uppercase
  static bool isUppercase(String str) {
    return str == str.toUpperCase();
  }

  /// check if the string is a number that's divisible by another
  ///
  /// [n] is a String or an int.
  static bool isDivisibleBy(String str, n) {
    try {
      return double.parse(str) % int.parse(n) == 0;
    } catch (e) {
      return false;
    }
  }

  /// check if the string is null
  static bool isNull(String str) {
    return str == null || str.length == 0;
  }

  /// check if the string's length falls in a range
  ///
  /// Note: this function takes into account surrogate pairs.
  static bool isLength(String str, int min, [int max]) {
    List surrogatePairs = _surrogatePairsRegExp.allMatches(str).toList();
    int len = str.length - surrogatePairs.length;
    return len >= min && (max == null || len <= max);
  }

  /// check if the string's length (in bytes) falls in a range.
  static bool isByteLength(String str, int min, [int max]) {
    return str.length >= min && (max == null || str.length <= max);
  }

  /// check if the string is a UUID (version 3, 4 or 5).
  static bool isUUID(String str, [version]) {
    if (version == null) {
      version = 'all';
    } else {
      version = version.toString();
    }

    RegExp pat = _uuid[version];
    return (pat != null && pat.hasMatch(str.toUpperCase()));
  }

  /// check if the string is a date
  static bool isDate(String str) {
    try {
      DateTime.parse(str);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// check if the string is a date that's after the specified date
  ///
  /// If `date` is not passed, it defaults to now.
  static bool isAfter(String str, [date]) {
    if (date == null) {
      date = new DateTime.now();
    } else if (isDate(date)) {
      date = DateTime.parse(date);
    } else {
      return false;
    }

    DateTime strDate;
    try {
      strDate = DateTime.parse(str);
    } catch (e) {
      return false;
    }

    return strDate.isAfter(date);
  }

  /// check if the string is a date that's before the specified date
  ///
  /// If `date` is not passed, it defaults to now.
  static bool isBefore(String str, [date]) {
    if (date == null) {
      date = new DateTime.now();
    } else if (isDate(date)) {
      date = DateTime.parse(date);
    } else {
      return false;
    }

    DateTime strDate;
    try {
      strDate = DateTime.parse(str);
    } catch (e) {
      return false;
    }

    return strDate.isBefore(date);
  }

  /// check if the string is in a array of allowed values
  static bool isIn(String str, values) {
    if (values == null || values.length == 0) {
      return false;
    }

    if (values is List) {
      values = values.map((e) => e.toString()).toList();
    }

    return values.indexOf(str) >= 0;
  }

  /// check if the string is a credit card
  static bool isCreditCard(String str) {
    String sanitized = str.replaceAll(new RegExp(r'[^0-9]+'), '');
    if (!_creditCard.hasMatch(sanitized)) {
      return false;
    }

    // Luhn algorithm
    int sum = 0;
    String digit;
    bool shouldDouble = false;

    for (int i = sanitized.length - 1; i >= 0; i--) {
      digit = sanitized.substring(i, (i + 1));
      int tmpNum = int.parse(digit);

      if (shouldDouble == true) {
        tmpNum *= 2;
        if (tmpNum >= 10) {
          sum += ((tmpNum % 10) + 1);
        } else {
          sum += tmpNum;
        }
      } else {
        sum += tmpNum;
      }
      shouldDouble = !shouldDouble;
    }

    return (sum % 10 == 0);
  }

  /// check if the string is an ISBN (version 10 or 13)
  static bool isISBN(String str, [version]) {
    if (version == null) {
      return isISBN(str, '10') || isISBN(str, '13');
    }

    version = version.toString();

    String sanitized = str.replaceAll(new RegExp(r'[\s-]+'), '');
    int checksum = 0;

    if (version == '10') {
      if (!_isbn10Maybe.hasMatch(sanitized)) {
        return false;
      }
      for (int i = 0; i < 9; i++) {
        checksum += (i + 1) * int.parse(sanitized[i]);
      }
      if (sanitized[9] == 'X') {
        checksum += 10 * 10;
      } else {
        checksum += 10 * int.parse(sanitized[9]);
      }
      return (checksum % 11 == 0);
    } else if (version == '13') {
      if (!_isbn13Maybe.hasMatch(sanitized)) {
        return false;
      }
      var factor = [1, 3];
      for (int i = 0; i < 12; i++) {
        checksum += factor[i % 2] * int.parse(sanitized[i]);
      }
      return (int.parse(sanitized[12]) - ((10 - (checksum % 10)) % 10) == 0);
    }

    return false;
  }

  /// check if the string is valid JSON
  static bool isJSON(str) {
    try {
      jsonDecode(str);
    } catch (e) {
      return false;
    }
    return true;
  }

  /// check if the string contains one or more multibyte chars
  static bool isMultibyte(String str) {
    return _multibyte.hasMatch(str);
  }

  /// check if the string contains ASCII chars only
  static bool isAscii(String str) {
    return _ascii.hasMatch(str);
  }

  /// check if the string contains any full-width chars
  static bool isFullWidth(String str) {
    return _fullWidth.hasMatch(str);
  }

  /// check if the string contains any half-width chars
  static bool isHalfWidth(String str) {
    return _halfWidth.hasMatch(str);
  }

  /// check if the string contains a mixture of full and half-width chars
  static bool isVariableWidth(String str) {
    return isFullWidth(str) && isHalfWidth(str);
  }

  /// check if the string contains any surrogate pairs chars
  static bool isSurrogatePair(String str) {
    return _surrogatePairsRegExp.hasMatch(str);
  }

  /// check if the string is a valid hex-encoded representation of a MongoDB ObjectId
  static bool isMongoId(String str) {
    return (isHexadecimal(str) && str.length == 24);
  }

  /// check if the string is a URL
  ///
  /// `options` is a `Map` which defaults to
  /// `{ 'protocols': ['http','https','ftp'], 'require_tld': true,
  /// 'require_protocol': false, 'allow_underscores': false,
  /// 'host_whitelist': false, 'host_blacklist': false }`.
  static bool isURL(String str, [Map options]) {
    if (str == null ||
        str.length == 0 ||
        str.length > 2083 ||
        str.indexOf('mailto:') == 0) {
      return false;
    }

    const Map default_url_options = {
      'protocols': ['http', 'https', 'ftp'],
      'require_tld': true,
      'require_protocol': false,
      'allow_underscores': false
    };

    options = _merge(options, default_url_options);

    var protocol,
        user,
        auth,
        host,
        hostname,
        port,
        portStr,
        path,
        query,
        hash,
        split;

    // check protocol
    split = str.split('://');
    if (split.length > 1) {
      protocol = _shift(split);
      if (options['protocols'].indexOf(protocol) == -1) {
        return false;
      }
    } else if (options['require_protocols'] == true) {
      return false;
    }
    str = split.join('://');

    // check hash
    split = str.split('#');
    str = _shift(split);
    hash = split.join('#');
    if (hash != null && hash != "" && new RegExp(r'\s').hasMatch(hash)) {
      return false;
    }

    // check query params
    split = str.split('?');
    str = _shift(split);
    query = split.join('?');
    if (query != null && query != "" && new RegExp(r'\s').hasMatch(query)) {
      return false;
    }

    // check path
    split = str.split('/');
    str = _shift(split);
    path = split.join('/');
    if (path != null && path != "" && new RegExp(r'\s').hasMatch(path)) {
      return false;
    }

    // check auth type urls
    split = str.split('@');
    if (split.length > 1) {
      auth = _shift(split);
      if (auth.indexOf(':') >= 0) {
        auth = auth.split(':');
        user = _shift(auth);
        if (!new RegExp(r'^\S+$').hasMatch(user)) {
          return false;
        }
        if (!new RegExp(r'^\S*$').hasMatch(user)) {
          return false;
        }
      }
    }

    // check hostname
    hostname = split.join('@');
    split = hostname.split(':');
    host = _shift(split);
    if (split.length > 0) {
      portStr = split.join(':');
      try {
        port = int.parse(portStr, radix: 10);
      } catch (e) {
        return false;
      }
      if (!new RegExp(r'^[0-9]+$').hasMatch(portStr) ||
          port <= 0 ||
          port > 65535) {
        return false;
      }
    }

    if (!isIP(host) && !isFQDN(host, options) && host != 'localhost') {
      return false;
    }

    if (options['host_whitelist'] == true &&
        options['host_whitelist'].indexOf(host) == -1) {
      return false;
    }

    if (options['host_blacklist'] == true &&
        options['host_blacklist'].indexOf(host) != -1) {
      return false;
    }

    return true;
  }

  /// Check if String is a valid CPF
  /// CPF is equivalent a SSN on Brazil
  static bool isValidCpf(String cpf) {
    if (cpf.length != 11) return false;
    if (cpf.split('').toSet().length == 1) return false;

    final nineDigits = cpf.substring(0, 9);
    final firstVerificationDigit = _calculateNextVerificationCpfDigit(nineDigits);
    final secondVerificationDigit = _calculateNextVerificationCpfDigit(nineDigits + firstVerificationDigit);
    final cpfCalculated = nineDigits + firstVerificationDigit + secondVerificationDigit;

    if (cpf != cpfCalculated) return false;
    else return true;
  }

  /// convert the input to a date, or null if the input is not a date
  static DateTime toDate(String str) {
    try {
      return DateTime.parse(str);
    } catch (e) {
      return null;
    }
  }

  /// convert the input to a float, or NAN if the input is not a float
  static double toFloat(String str) {
    try {
      return double.parse(str);
    } catch (e) {
      return double.nan;
    }
  }

  /// convert the input to a float, or NAN if the input is not a float
  static double toDouble(String str) {
    return toFloat(str);
  }

  /// convert the input to an integer, or NAN if the input is not an integer
  static num toInt(String str, {int radix: 10}) {
    try {
      return int.parse(str, radix: radix);
    } catch (e) {
      try {
        return double.parse(str).toInt();
      } catch (e) {
        return double.nan;
      }
    }
  }

  /// convert the input to a boolean.
  ///
  /// Everything except for '0', 'false' and ''
  /// returns `true`. In `strict` mode only '1' and 'true' return `true`.
  static bool toBoolean(String str, [bool strict]) {
    if (strict == true) {
      return str == '1' || str == 'true';
    }
    return str != '0' && str != 'false' && str != '';
  }

  /// trim characters (whitespace by default) from both sides of the input
  static String trim(String str, [String chars]) {
    RegExp pattern = (chars != null)
        ? new RegExp('^[$chars]+|[$chars]+\$')
        : new RegExp(r'^\s+|\s+$');
    return str.replaceAll(pattern, '');
  }

  /// trim characters from the left-side of the input
  static String ltrim(String str, [String chars]) {
    var pattern =
        chars != null ? new RegExp('^[$chars]+') : new RegExp(r'^\s+');
    return str.replaceAll(pattern, '');
  }

  /// trim characters from the right-side of the input
  static String rtrim(String str, [String chars]) {
    var pattern =
        chars != null ? new RegExp('[$chars]+\$') : new RegExp(r'\s+$');
    return str.replaceAll(pattern, '');
  }

  /// remove characters that do not appear in the whitelist.
  ///
  /// The characters are used in a RegExp and so you will need to escape
  /// some chars.
  static String whitelist(String str, String chars) {
    return str.replaceAll(new RegExp('[^' + chars + ']+'), '');
  }

  /// remove characters that appear in the blacklist.
  ///
  /// The characters are used in a RegExp and so you will need to escape
  /// some chars.
  static String blacklist(String str, String chars) {
    return str.replaceAll(new RegExp('[' + chars + ']+'), '');
  }

  /// remove characters with a numerical value < 32 and 127.
  ///
  /// If `keep_new_lines` is `true`, newline characters are preserved
  /// `(\n and \r, hex 0xA and 0xD)`.
  static String stripLow(String str, [bool keepNewLines]) {
    String chars = keepNewLines == true
        ? '\x00-\x09\x0B\x0C\x0E-\x1F\x7F'
        : '\x00-\x1F\x7F';
    return blacklist(str, chars);
  }

  /// replace `<`, `>`, `&`, `'` and `"` with HTML entities
  static String escape(String str) {
    return (str
        .replaceAll(new RegExp(r'&'), '&amp;')
        .replaceAll(new RegExp(r'"'), '&quot;')
        .replaceAll(new RegExp(r"'"), '&#x27;')
        .replaceAll(new RegExp(r'<'), '&lt;')
        .replaceAll(new RegExp(r'>'), '&gt;'));
  }

  /// canonicalize an email address.
  ///
  /// `options` is an `Map` which defaults to
  /// `{ lowercase: true }`. With lowercase set to true, the local part of the
  /// email address is lowercased for all domains; the hostname is always
  /// lowercased and the local part of the email address is always lowercased
  /// for hosts that are known to be case-insensitive (currently only GMail).
  /// Normalization follows special rules for known providers: currently,
  /// GMail addresses have dots removed in the local part and are stripped of
  /// tags (e.g. `some.one+tag@gmail.com` becomes `someone@gmail.com`) and all
  /// `@googlemail.com` addresses are normalized to `@gmail.com`.
  static String normalizeEmail(String email, [Map options]) {
    options = _merge(options, _default_normalize_email_options);
    if (isEmail(email) == false) {
      return '';
    }

    List parts = email.split('@');
    parts[1] = parts[1].toLowerCase();

    if (options['lowercase'] == true) {
      parts[0] = parts[0].toLowerCase();
    }

    if (parts[1] == 'gmail.com' || parts[1] == 'googlemail.com') {
      if (options['lowercase'] == false) {
        parts[0] = parts[0].toLowerCase();
      }
      parts[0] = parts[0].replaceAll('\.', '').split('+')[0];
      parts[1] = 'gmail.com';
    }
    return parts.join('@');
  }
}

_shift(List l) {
  if (l.length >= 1) {
    var first = l.first;
    l.removeAt(0);
    return first;
  }
  return null;
}

Map _merge(Map obj, defaults) {
  if (obj == null) {
    obj = new Map();
  }
  defaults.forEach((key, val) => obj.putIfAbsent(key, () => val));
  return obj;
}

String _calculateNextVerificationCpfDigit(String cpf) {
  int sum = 0;
  int j = cpf.length + 1;

  cpf.split('').forEach((digit) {
    sum += (int.tryParse(digit) ?? 0) * j;
    j--;
  });

  final digit = 11 - (sum % 11);
  return ((digit > 9) ? 0 : digit).toString();
}
