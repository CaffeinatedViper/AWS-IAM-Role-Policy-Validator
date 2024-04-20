import json
from unittest.mock import patch, mock_open
from src.main import check_for_asterisk
import unittest


class TestCheckForaAsterisk(unittest.TestCase):

    def test_loads_valid_json_without_asteriks(self):
        data = json.dumps({
            "PolicyName": "TestPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "1",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::bucket/*"],

                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with patch("src.main.load_json_file", return_value=json.loads(data)):
                result = check_for_asterisk("fake_path.json")
                self.assertTrue(result)

    def test_loads_valid_json_with_asteriks(self):
        data = json.dumps({
            "PolicyName": "TestPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "1",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*",
                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with patch("src.main.load_json_file", return_value=json.loads(data)):
                result = check_for_asterisk("fake_path.json")
                self.assertFalse(result)

    def test_loads_valid_json_with_many_statments_and_asterisk(self):
        data = json.dumps({
            "PolicyName": "TestPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "1",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::bucket/*"],
                    },
                    {
                        "Sid": "2",
                        "Effect": "Allow",
                        "Action": ["iam:ListRoles", "iam:ListUsers"],
                        "Resource": ["arn:aws:s3:::bucket/*"],
                    },
                    {
                        "Sid": "3",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*",
                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with patch("src.main.load_json_file", return_value=json.loads(data)):
                result = check_for_asterisk("fake_path.json")
                self.assertFalse(result)

    def test_loads_valid_json_with_many_statments_and_without_asterisk(self):
        data = json.dumps({
            "PolicyName": "TestPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "1",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::bucket/*"],
                    },
                    {
                        "Sid": "2",
                        "Effect": "Allow",
                        "Action": ["iam:ListRoles", "iam:ListUsers"],
                        "Resource": ["arn:aws:s3:::bucket/*"],
                    },
                    {
                        "Sid": "3",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::confidential-data", "arn:aws:s3:::confidential-data/*"],
                    }
                ]
            }
        })
        with patch("builtins.open", mock_open(read_data=data)):
            with patch("src.main.load_json_file", return_value=json.loads(data)):
                result = check_for_asterisk("fake_path.json")
                self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
