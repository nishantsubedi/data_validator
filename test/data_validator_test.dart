import 'package:flutter_test/flutter_test.dart';

import 'package:data_validator/data_validator.dart';

void main() {
  test('check if is email', () {
    expect(DataValidator.isEmail("john@abc.com"), true);
  });
}
