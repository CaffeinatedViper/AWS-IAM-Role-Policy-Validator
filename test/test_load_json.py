import json
import unittest
from unittest.mock import patch, mock_open
from jsonschema.exceptions import ValidationError
from src.main import load_json_file


class TestLoadJsonFile(unittest.TestCase):
    def test_load_valid_json_file(self):
        file_path = "./resources/valid.json"
        result = load_json_file(file_path)
        self.assertIsInstance(result, dict)

    def test_raise_file_not_found_error(self):
        file_path = "./resources/nonexistent_file.json"
        with self.assertRaises(FileNotFoundError):
            load_json_file(file_path)

    def test_raise_json_decode_error_from_file(self):
        file_path = "./resources/invalid_json.json"
        with self.assertRaises(Exception):
            load_json_file(file_path)

    def test_raise_validation_error_from_file(self):
        file_path = "./resources/invalid_policy_format.json"
        with self.assertRaises(ValidationError):
            load_json_file(file_path)

    def test_policy_action_not_found_error(self):
        data = json.dumps({
            "PolicyName": "TestPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "1",
                        "Effect": "Allow",
                        "Resource": "*",
                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with self.assertRaises(ValidationError):
                load_json_file(data)

    def test_policy_statement_not_found_error(self):
        data = json.dumps({
            "PolicyName": "root",
            "PolicyDocument": {
                "Version": "2012-10-17"
            }})
        with patch("builtins.open", mock_open(read_data=data)):
            with self.assertRaises(ValidationError):
                load_json_file(data)

    def test_policy_with_extra_unexpected_fields(self):
        data = json.dumps({
            "PolicyName": "FieldPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [],
                "UnexpectedField": "UnexpectedValue"
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with self.assertRaises(ValidationError):
                load_json_file(data)

    def test_policy_without_policy_name(self):
        data = json.dumps({

                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": "*"
                        }
                    ]
                }

        })
        with patch("builtins.open", mock_open(read_data=data)):
            with self.assertRaises(ValidationError):
                load_json_file(data)

    def test_policy_without_sid_name(self):
        data = json.dumps({
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListRoles",
                            "iam:ListUsers"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with self.assertRaises(ValidationError):
                result = load_json_file(data)
                self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
