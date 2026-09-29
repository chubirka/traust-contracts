# enums/v2

The v2 registry vocabularies. Each file defines one vocabulary and says how
every value of the v1 vocabularies it replaces converts into v2.

v1 does not go away. Stored documents and ledger events keep their v1 values,
because ledger event IDs hash them. They are converted to v2 when read. So
every v1 value must have a conversion, and the checks below enforce that.

The directory is empty until the v2 vocabularies are decided.
`tests/fixtures/enums_v2/` holds an illustrative set that exercises the
format; its values are not decisions.

## File format

The shape is defined by [`../format/v2.schema.json`](../format/v2.schema.json).

| Field | Meaning |
|---|---|
| `name` | Registry name. The file is `<name with _ replaced by ->.json`. |
| `description` | The one question the vocabulary answers. |
| `values` | Allowed values, a plain string list as in v1. |
| `definitions` | What each value means; exactly one entry per value. |
| `standard` | The standard followed (`name`, optional `url`, `relationship` `exact` or `adapted`, and a `note` saying what differs when adapted), or `{"none": "<why>"}`. |
| `since` | The traust-contracts version the file first shipped in. |
| `replaces_v1` | The v1 vocabularies this file converts. Each v1 vocabulary is converted by exactly one v2 file. |
| `aliases_from_v1` | The conversion rules. |

## Conversion rules

Each alias converts one v1 value:

```json
{
  "from": {"enum": "review_item_status", "value": "rejected"},
  "when": [{"field": "resolution_note", "matches": "^bulk-closed "}],
  "to": [{"enum": "review_status", "value": "closed_unreviewed"}]
}
```

- `from` names a v1 vocabulary and one of its values.
- `to` lists everything that value becomes. Each item does one of three
  things:
  - `{"enum": <v2 name>, "value": <v2 value>}` sets a v2 vocabulary. Several
    of them express a value that splits: v1 validity `hardening` becomes
    `validity: true_positive` plus `finding_kind: weakness`. The v2 schema
    decides which field stores each vocabulary.
  - `{"set": {"field": <name>, "value": <JSON>}}` sets a field that is not a
    vocabulary, such as `is_default: true` for v1 `ref_kind: default`.
  - `{"drop": "<where the information lives instead>"}` records that the
    value has no v2 counterpart.
- `when` (optional) lists conditions that must all hold, on fields of the
  same object that holds the v1 value. Each condition names a `field` and one
  test: `equals`, `in`, `matches` (a regular expression, searched), or
  `contains_any` (the field is an array holding one of the values).
- `note` (optional) explains a choice.

To convert a v1 value, a reader:

1. Finds the v2 file whose `replaces_v1` lists the v1 vocabulary.
2. Takes that file's aliases for the value, in file order.
3. Applies the first conditional alias whose conditions all hold. If none
   holds, it applies the value's single unconditional alias.

Renames, merges (several v1 values to one v2 value) and splits all fall out
of this. No alias may set the same vocabulary or field twice.

## Checks

`python3 ci/enum_v2.py` checks every file here, and
`tests/test_enum_v2_format.py` runs it in CI. It fails when:

- a file does not match the format schema
- `definitions` and `values` differ
- a file name does not match its `name`, or a name is used twice
- a v1 vocabulary is unknown, or converted by more than one file
- an alias converts a vocabulary its file does not replace, or a value that
  vocabulary does not have
- a v1 value has no unconditional alias, or has two
- a conditional alias comes after the unconditional one, so it can never
  apply
- a target names a v2 vocabulary or value that does not exist
- an alias sets a vocabulary or field twice
- an adapted standard has no note
