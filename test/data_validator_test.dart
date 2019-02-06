import 'package:flutter_test/flutter_test.dart';

import 'package:data_validator/data_validator.dart';

void main() {
  test('check if is email', () {
    expect(DataValidator.isEmail("john@abc.com"), true);
  });

  group('isValidCpf', () {
    group('when is invalid', () {
      test('it returns invalid', () {
        expect(DataValidator.isValidCpf("00000000000"), false);
        expect(DataValidator.isValidCpf("11111111111"), false);
        expect(DataValidator.isValidCpf("anything"), false);
      });
    });

    group('when is valid', () {
      test('it returns valid', () {
        expect(DataValidator.isValidCpf("55403106081"), true);
        expect(DataValidator.isValidCpf("65925699050"), true);
      });
    });
  });
}
