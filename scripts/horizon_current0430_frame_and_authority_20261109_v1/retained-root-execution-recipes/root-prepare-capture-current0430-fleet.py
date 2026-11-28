from pathlib import Path
import ast
old=Path('/tmp/continuations0230-qualified-phase-required-source-20261109-v1/capture-current0230-fleet.py');p=Path('/tmp/continuations0430-driver12-helper35-final6-source-20261109-v1');p.mkdir(mode=0o700)
s=old.read_text();pairs={'current0230':'current0430','T023022Z':'T043022Z','2026-11-09T02:30:22Z':'2026-11-09T04:30:22Z','horizon-first-lane-current0100-fleet-plan-20261109-v1/fleet-plan.json':'horizon-first-lane-current0230-fleet-plan-20261109-v1/fleet-plan.json','ROOT_CURRENT0230':'ROOT_CURRENT0430','GENUINE0230FLEET':'GENUINE0430FLEET'}
for a,b in pairs.items():s=s.replace(a,b)
needle="save('fleet-plan.json', fp)";assert s.count(needle)==1
extra='''# Add exact observed0230 terminal history and actual new repair qualifications,
# preserving every older gate, raw promise and tracked service.
for unit in ['horizon-qualify-185-capped-cold-positive-positive-0230-20261109-next.service','horizon-guard-185-capped-cold-positive-positive-0230-20261109-next.service','horizon-positive185-original-actual0230-r3-20261109-next.service']:
    if unit not in fp['tracked_units']:fp['tracked_units'].append(unit)
old185=dict(fp['gates']['185']);evidence=list(old185['evidence'])
for path in ['/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/terminal.json','/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_QUALIFIED_OPERATION38_BINDINGS.json','/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_EXACT0230_SUCCESSFUL_READER_RETIRED.json','/home/sol/.jetstreamer-private/current0430-guard-window-booking-20261109-v1/ROOT_NORMAL6_CURRENT0430_GUARD_DATA512_BOOKING.json']:
    binding=b(Path(path));assert binding['path'] not in {r['path']for r in evidence};evidence.append(binding)
fp['gates']['185']=dict(old185,evidence=evidence,next_action=old185['next_action']+' Latest0230actor reached Main then failed cold initialization with its own resource census ENOENT; actual drained terminal and zeroOOM evidence retained. Driver12 storage race repair, Helper35, Planner6, Final6 and Operation38 are now qualified/sealed; exact0230successfulreader aliases retired without payload/resourcecredit. Continue fresh current Frame/reader/accounting/guard/admission through actual worker execution. Full185route remains unqualified; no oldclock renewal or archive/publication authority.')
assert fp['gates']['185']['state']==old185['state']=='failed-needs-repair'
'''
s=s.replace(needle,extra+needle);ast.parse(s);(p/'capture-current0430-fleet.py').write_text(s);(p/'PARTIAL_HANDOFF.md').write_text('Root current0430source in preparation. Only capture-current0430-fleet.py is ready; no complete Frame/resource/launchchain exists yet. Existing fleet capture reused with explicit currentclock/namespace, actual0230predecessor and additive terminal185/currentqualification evidence. Runonlyafter actual0430observer/statusmaintenance completed. No future0430digest or admission claimed.\n');print(p)
