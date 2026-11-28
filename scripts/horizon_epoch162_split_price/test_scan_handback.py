from unittest import TestCase

import scan_handback as scan


class ScannerHandbackTest(TestCase):
    def setUp(self):
        self.unit = 'horizon-168-private-archive-verify-4.service'
        self.ad = {'path':'admission'}
        self.s = dict(Id=self.unit,ActiveState='inactive',Job='',MainPID='0',ControlPID='0',ControlGroup='',InvocationID='af'*16)
        self.entered = ({'invocation': self.s['InvocationID']},{'path':'started'})

    def result(self, *, s=None, scanner=None, started=None, end=None, expired=None, now=6):
        return scan.disposition(self.unit,self.ad,s or self.s,scanner,started,end,expired,now,5)

    def test_unstarted_and_enqueued_do_not_return_the_donor(self):
        for state in ('inactive','activating','deactivating'):
            with self.assertRaises(ValueError):
                self.result(s=self.s|{'ActiveState':state})
        with self.assertRaises(ValueError):
            self.result(s=self.s|{'Job':'402/start'},expired={'admission':self.ad,'unit':self.unit})
        with self.assertRaises(ValueError):
            self.result(expired={'admission':self.ad,'unit':self.unit},now=5)

    def test_positive_accounting_for_the_exact_scanner_only(self):
        native=self.s|{'ActiveState':'active','ControlGroup':'/horizonaudit.slice/'+self.unit,'MainPID':'5'}
        budget=dict(native=native,admission=self.ad,started=self.entered[1])
        self.assertEqual(self.result(s=native,scanner=budget,started=self.entered),'funded-active-scanner')
        for change in ({'admission':{}},{'started':{}},{'native':native|{'InvocationID':'other'}}):
            with self.assertRaises(ValueError):
                self.result(s=native,scanner=budget|change,started=self.entered)

    def test_confirmed_drain_and_confirmed_never_start(self):
        close={'invocation':self.s['InvocationID']}
        self.assertEqual(self.result(started=self.entered,end=close),'native-terminal-drained')
        self.assertEqual(self.result(end=close),'native-terminal-drained')
        with self.assertRaises(ValueError):
            self.result(started=self.entered,end={'invocation':'foreign'})
        with self.assertRaises(ValueError):
            self.result(s=self.s|{'MainPID':'5'},end=close)
        no_start={'admission':self.ad,'unit':self.unit}
        self.assertEqual(self.result(expired=no_start),'expired-and-never-started')
        with self.assertRaises(ValueError):
            self.result(expired=no_start|{'admission':{}})
