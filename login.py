#!/usr/bin/env python
from argparse import ArgumentParser
import json
import eero
import six
import sys

class CookieStore(eero.SessionStorage):
    def __init__(self, cookie_file):
        from os import path
        self.cookie_file = path.abspath(cookie_file)

        try:
            with open(self.cookie_file, 'r') as f:
                self.__cookie = f.read()
        except IOError:
            self.__cookie = None

    @property
    def cookie(self):
        return self.__cookie

    @cookie.setter
    def cookie(self, cookie):
        self.__cookie = cookie
        with open(self.cookie_file, 'w+') as f:
            f.write(self.__cookie)


session = CookieStore('session.cookie')
eero = eero.Eero(session)


def print_json(data):
    print(json.dumps(data, indent=4))


if __name__ == '__main__':
    if eero.needs_login():
        login = six.moves.input('Your eero login (email address or phone number): ')
        user_token = eero.login(login)
        verification_code = six.moves.input('Verification key from email or SMS: ')
        try:
            eero.login_verify(verification_code, user_token)
            print('Login successful')
        except Exception as e:
            print("Login failed: %s" % str(e))
    else:
        print("Logged in as: %s" % eero.user['name'])
