#!/usr/bin/env python3
"""Offline public-release checks. Not a semantic privacy or live-model guarantee."""
from pathlib import Path
import hashlib
import json
import re
import sys
from urllib.parse import unquote

if sys.version_info < (3, 9):
    sys.exit('Python 3.9 or newer is required for this validator.')

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/sean'
errors = []
def fail(message):
    errors.append(message)
def files_under(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob('*') if p.is_file()
            and p.relative_to(root).parts[0] != '.git'}
def check_manifest(name, base, exclusions=()):
    try:
        manifest = json.loads((ROOT / name).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        fail(f'{name}: {exc}')
        return {}
    rows = manifest.get('files', [])
    names = [x.get('path') for x in rows]
    actual = files_under(base)
    for excluded in exclusions:
        actual.pop(excluded, None)
    if len(names) != len(set(names)):
        fail(f'{name}: duplicate paths')
    if set(names) != set(actual):
        fail(f'{name}: inventory mismatch: missing={sorted(set(actual)-set(names))}, extra={sorted(set(names)-set(actual))}')
    for row in rows:
        path = base / row.get('path', '')
        if not path.resolve().is_relative_to(base.resolve()) or path.is_symlink():
            fail(f'{name}: unsafe path')
            continue
        if path.is_file():
            data = path.read_bytes()
            if row.get('bytes') != len(data) or row.get('sha256') != hashlib.sha256(data).hexdigest():
                fail(f'{name}: hash/size mismatch: {row.get("path")}')
    return manifest

# Update this explicit allowlist intentionally when adding a release artifact.
# A regenerated manifest alone must not legitimize unexpected files.
ALLOWED_RELEASE_FILES = {
    '.gitattributes',
    '.gitignore',
    'LICENSE',
    'PRIVACY.md',
    'README.md',
    'release-manifest.json',
    'scripts/validate.py',
    'skill-manifest.json',
    'skills/sean/ARCHITECTURE.md',
    'skills/sean/LICENSE',
    'skills/sean/SKILL.md',
    'skills/sean/agents/openai.yaml',
    'skills/sean/evidence/README.md',
    'skills/sean/evidence/public-examples.md',
    'skills/sean/evidence/public-records.jsonl',
    'skills/sean/references/ethics.md',
    'skills/sean/references/evidence.md',
    'skills/sean/references/goals.md',
    'skills/sean/references/preferences.md',
    'skills/sean/references/profile.md',
    'skills/sean/references/trace.md',
    'skills/sean/references/understanding.md',
    'skills/sean/routes/decide.md',
    'skills/sean/routes/ethics.md',
    'skills/sean/routes/express.md',
    'skills/sean/routes/inquire.md',
    'skills/sean/routes/reflect.md',
    'tests/scenarios.json',
}
allowed_directories = {parent.as_posix() for name in ALLOWED_RELEASE_FILES
                       for parent in Path(name).parents if parent.as_posix() != '.'}
for artifact in ROOT.rglob('*'):
    relative = artifact.relative_to(ROOT).as_posix()
    if artifact.relative_to(ROOT).parts[0] == '.git':
        continue
    if artifact.is_symlink():
        fail(f'Symlink not allowed: {relative}')
    elif artifact.is_dir() and relative not in allowed_directories:
        fail(f'Unexpected release directory: {relative}')
actual_names = set(files_under(ROOT))
if actual_names != ALLOWED_RELEASE_FILES:
    fail(f'Release allowlist mismatch: unexpected={sorted(actual_names-ALLOWED_RELEASE_FILES)}, missing={sorted(ALLOWED_RELEASE_FILES-actual_names)}')

skill_manifest = check_manifest('skill-manifest.json', SKILL)
check_manifest('release-manifest.json', ROOT, ('release-manifest.json',))
if skill_manifest.get('version') != '0.2.0-public' or len(skill_manifest.get('files', [])) != 19:
    fail('Expected version 0.2.0-public and 19 skill files')
# Keep the authorized MIT notice intact, including in the installable skill.
expected_license_sha256 = 'd99f6e98778c8711f72ef575c5764a36c2a7301041286bf3377c5c56c0a627f8'
for license_path in (ROOT/'LICENSE', SKILL/'LICENSE'):
    if not license_path.is_file() or hashlib.sha256(license_path.read_bytes()).hexdigest() != expected_license_sha256:
        fail(f'MIT license missing or changed: {license_path.relative_to(ROOT)}')

expected_keys = {'id', 'kind', 'representation', 'statement', 'scope', 'limits', 'verbatim'}
allowed_kinds = {'direct_expression_paraphrase', 'case_interpretation_paraphrase',
                 'bounded_interpretation_paraphrase', 'calibrated_expression_paraphrase', 'hypothesis', 'method'}
records = []
try:
    for line in (SKILL/'evidence/public-records.jsonl').read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        records.append(row)
        if set(row) != expected_keys or row.get('kind') not in allowed_kinds or row.get('verbatim') is not False:
            fail(f'Invalid public record schema: {row.get("id")}')
        expected_rep = 'editorial_method' if row.get('kind') == 'method' else 'sanitized_paraphrase'
        if row.get('representation') != expected_rep:
            fail(f'Invalid representation: {row.get("id")}')
        for key in ('statement', 'scope', 'limits'):
            if not isinstance(row.get(key), str) or not row[key].strip():
                fail(f'Missing content: {row.get("id")}/{key}')
except (OSError, ValueError) as exc:
    fail(f'Cannot parse records: {exc}')
ids = [row.get('id') for row in records]
if ids != [f'P{x:02}' for x in range(1, 32)]:
    fail('Expected P01 to P31 exactly once in order')
forbidden_names = {'quotes.jsonl', 'claims.jsonl', 'calibration-context.md', 'source-manifest.json'}
forbidden_fields = {'conversation_id', 'node_id', 'message_id', 'timestamp_unix', 'source_sha256',
                    'native_source_workspace_path', 'native_pointer', 'character_span',
                    'namespaced_aliases', 'source_record', 'calibration_addenda'}
patterns = [r'gh[pousr]_[A-Za-z0-9]{20,}', r'github_pat_[A-Za-z0-9_]{20,}', r'\bsk-[A-Za-z0-9_-]{20,}',
            r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            r'(?i)[A-Z]:[\\/](?:Users|Work|Projects)[\\/]', r'/(?:Users|home|workspace|tmp)/[^\s<>]+',
            r'\bCV2-E\d{4}\b', r'\bC21-Q\d+\b', r'\b(?:D\d{2}|I\d{2}|M\d{2}|H-C[12]|U07)\b']
all_files = files_under(ROOT)
link_count = reference_count = 0
for relative, path in all_files.items():
    if path.name in forbidden_names or path.is_symlink():
        fail(f'Original evidence file or symlink: {relative}')
    try:
        content = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        fail(f'Non-text file: {relative}')
        continue
    if b'\r' in path.read_bytes() or '\x00' in content:
        fail(f'Unexpected CR/NUL bytes: {relative}')
    # This checker must name excluded fields and patterns to detect them.
    if relative != 'scripts/validate.py':
        for field in forbidden_fields:
            if re.search(r'["\']' + re.escape(field) + r'["\']\s*:', content):
                fail(f'Private source field: {relative}/{field}')
        for pattern in patterns:
            if re.search(pattern, content):
                fail(f'Private locator or common secret pattern: {relative}')
    if path.suffix == '.md':
        for public_id in re.findall(r'\bP\d{2}\b', content):
            reference_count += 1
            if public_id not in ids:
                fail(f'Unknown public record {public_id}: {relative}')
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', content):
            target = target.strip().split(' "', 1)[0].strip('<>')
            if re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                continue
            if target.startswith('#'):
                fail(f'Unchecked fragment-only link: {relative}/{target}')
                continue
            target = unquote(target.split('#', 1)[0])
            dest = (path.parent / target).resolve()
            link_count += 1
            if not dest.is_relative_to(ROOT.resolve()) or not dest.exists():
                fail(f'Broken or escaped local link: {relative}/{target}')
entry = (SKILL/'SKILL.md').read_text(encoding='utf-8')
metadata = (SKILL/'agents/openai.yaml').read_text(encoding='utf-8')
if not entry.startswith('---\nname: sean\ndescription: ') or '\n---\n' not in entry[4:]:
    fail('Invalid skill frontmatter')
if '$sean' not in metadata or 'allow_implicit_invocation: true' not in metadata:
    fail('Agent metadata mismatch')
if len(list((SKILL/'routes').glob('*.md'))) != 5 or len(list((SKILL/'references').glob('*.md'))) != 7:
    fail('Expected 5 routes and 7 reference files')
examples = (SKILL/'evidence/public-examples.md').read_text(encoding='utf-8')
if re.findall(r'^## (E\d{2})：', examples, flags=re.M) != [f'E{x:02}' for x in range(1, 6)]:
    fail('Expected 5 numbered public examples')
try:
    scenarios = json.loads((ROOT/'tests/scenarios.json').read_text(encoding='utf-8'))
    if scenarios.get('automated_model_test') is not False or len(scenarios.get('scenarios', [])) != 10:
        fail('Expected 10 manual model behavior scenarios')
except (OSError, ValueError) as exc:
    fail(f'Cannot parse scenarios: {exc}')
if errors:
    print('FAIL\n' + '\n'.join('- ' + e for e in errors))
    sys.exit(1)
print(f'PASS: {len(all_files)} release files; 19 skill files; 31 public records; 5 examples; 10 behavior scenarios')
print(f'PASS: inventory, SHA-256, record schema, {link_count} local links and {reference_count} record references')
print('PASS: no original evidence files, forbidden fields, private locators or common secret patterns detected')
print('LIMIT: structural checks are not a semantic privacy guarantee or a live-host/model behavior test')
