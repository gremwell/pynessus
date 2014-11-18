"""
Copyright 2014 Quentin Kaiser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


class Scan(object):
    """
    A Nessus Scan instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self):
        """Constructor"""
        self._status = None
        self._name = None
        self._description = None
        self._tag = None
        self._read = True
        self._timestamp = 0
        self._last_modification_date = 0
        self._object_id = -1
        self._creation_date = 0
        self._user_permissions = 0
        self._default_permissions = 0
        self._owner = None
        self._shared = False
        self._type = None
        self._id = None
        self._uuid = None
        self._policy = None
        self._scanner = None
        self._custom_targets = None
        self._target_file_name = None

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        self._status = status

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, tag):
        self._tag = tag

    @property
    def read(self):
        return self._read

    @read.setter
    def read(self, read):
        self._read = read

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self._timestamp = timestamp

    @property
    def last_modification_date(self):
        return self._last_modification_date

    @last_modification_date.setter
    def last_modification_date(self, last_modification_date):
        self._last_modification_date = last_modification_date

    @property
    def object_id(self):
        return self._object_id

    @object_id.setter
    def object_id(self, object_id):
        self._object_id = object_id

    @property
    def creation_date(self):
        return self._creation_date

    @creation_date.setter
    def creation_date(self, creation_date):
        self._creation_date = creation_date

    @property
    def user_permissions(self):
        return self._user_permissions

    @user_permissions.setter
    def user_permissions(self, user_permissions):
        self._user_permissions = user_permissions

    @property
    def default_permissions(self):
        return self._default_permissions

    @default_permissions.setter
    def default_permissions(self, default_permissions):
        self._default_permissions = default_permissions

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, owner):
        self._owner = owner

    @property
    def shared(self):
        return self._shared

    @shared.setter
    def shared(self, shared):
        self._shared = shared

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type):
        self._type = _type

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, _id):
        self._id = _id

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, _uuid):
        self._uuid = _uuid

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy

    @property
    def scanner(self):
        return self._scanner

    @scanner.setter
    def scanner(self, scanner):
        self._scanner = scanner

    @property
    def custom_targets(self):
        return self._custom_targets

    @custom_targets.setter
    def custom_targets(self, custom_targets):
        self._custom_targets = custom_targets

    @property
    def target_file_name(self):
        return self._target_file_name

    @target_file_name.setter
    def target_file_name(self, target_file_name):
        self._target_file_name = target_file_name