# data_validator

A simple data validation 

## Getting Started

In your project add the dependency:

```yml
dependencies:
  ...
  data_validator: any
```

## Usage example


```dart
import 'package:data_validator/data_validator.dart';
```


```dart
import 'package:data_validator/data_validator.dart';

void main() {
  print('running');
  print(DataValidator.isEmail("john@abc.com"));
  print(DataValidator.isPhoneNumber("9841580604"));
  print(DataValidator.isURL("https://www.google.com"));
  print(DataValidator.isFloat("4.5"));
  print(DataValidator.isIP("127.0.0.1"));
  print(DataValidator.toBoolean('true'));
  print(DataValidator.isJSON('{"name" : "John Doe"}'));
}


```