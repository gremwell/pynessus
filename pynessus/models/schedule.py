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

import datetime

from pynessus.models.scan import Scan


class Frequencies:

    ONE_TIME = "ONETIME"
    DAILY = "DAILY;INTERVAL=%d"
    WEEKLY = "FREQ=WEEKLY;INTERVAL=%d;BYDAY=%s" #BYDAY = MO,TU,WE,TH,FR,SA,SU
    MONTHLY_BYMONTHDAY = "FREQ=MONTHLY;INTERVAL=%d;BYMONTHDAY=%d" #day of the month
    MONTHLY_BYDAY = "FREQ=MONTHLY;INTERVAL=%d;BYDAY=%d%s" #2FR = second friday of the month
    YEARLY = "FREQ=YEARLY;INTERVAL=%d"

    def __init__(self):
        return

    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

class RRule(object):

    def __init__(self, frequency=Frequencies.ONE_TIME, interval=1, day=None):
        if frequency != Frequencies.ONE_TIME:
            if frequency == Frequencies.DAILY or frequency == Frequencies.YEARLY:
                self.value = frequency % (interval)
            else:
                self.value = frequency % (interval, day)
        else:
            self.value = frequency

    def __str__(self):
        return self.value


class NotificationFilter(object):

    def __init__(self, _filter, quality, value):
        self.filter = _filter
        self.quality = quality
        self.value = value


class Schedule(Scan):
    """
    A Nessus Schedule instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self):
        """Constructor"""
        super(Schedule, self).__init__()
        self._uuid = None
        self._rrules = None
        self._starttime = None
        self._timezone = None
        self._emails = []
        self._notifications_filter_type = "and"
        self._notifications_filters = []

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, uuid):
        self._uuid = uuid

    @property
    def rrules(self):
        return self._rrules

    @rrules.setter
    def rrules(self, rrules):
        self._rrules = rrules

    @property
    def starttime(self):
        return self._starttime

    @starttime.setter
    def starttime(self, starttime):
        if type(starttime) is int:
            self._starttime = datetime.datetime.fromtimestamp(starttime).strftime('%Y%m%dT%H%M%S')
        else:
            self._starttime = starttime

    @property
    def timezone(self):
        return self._timezone

    @timezone.setter
    def timezone(self, timezone):
        self._timezone = timezone

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy

    @property
    def emails(self):
        return self._emails

    @emails.setter
    def emails(self, emails):
        self._emails = emails

    @property
    def notification_filters(self):
        return self._notifications_filters

    @notification_filters.setter
    def notification_filters(self, notifications_filters):
        self._notifications_filters = notifications_filters

    @property
    def notification_filter_type(self):
        return self._notifications_filter_type

    @notification_filter_type.setter
    def notification_filter_type(self, notifications_filter_type):
        self._notifications_filter_type = notifications_filter_type