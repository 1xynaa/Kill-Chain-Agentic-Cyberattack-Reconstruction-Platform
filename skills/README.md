# Shared Project Skills

This directory is the shared home for project-specific skills, playbooks, prompts, and reusable investigation procedures.

## Conventions

- Add one self-contained skill per subdirectory.
- Each skill should include a `SKILL.md` with purpose, inputs, outputs, workflow, safety limits, and verification steps.
- Keep secrets, API keys, credentials, uploaded evidence, generated reports, and local workspaces out of Git.
- Prefer deterministic, structured outputs so skills can feed the agent, mapper, graph, and report engine.
- Record assumptions and uncertainty explicitly.
- Coordinate changes with the team before modifying shared interfaces.

See `PROJECT_CONTEXT.md` for the current system brief and collaboration rules.
