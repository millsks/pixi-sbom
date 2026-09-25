# scorecard fixture

One recorded response from `api.securityscorecards.dev`, trimmed to the fields the tool reads
(`score`, `date`, `checks[].name` / `.score` / `.reason`). The file name is the cache key the
lookup uses — the project path with `/` replaced by `-` — so copying it into
`<cache>/scorecard/` answers the lookup offline. `Branch-Protection` has the `-1` score the
service reports for a check that could not run, which is never a failing check.
