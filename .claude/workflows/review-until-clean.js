export const meta = {
  name: 'review-until-clean',
  description: 'Three reviewers (Rust code, architecture, UI/UX) review the changes; issues are fixed and re-reviewed until all three report none',
  whenToUse: 'After any code change in this repository, before reporting the work as done or committing it',
  phases: [
    { title: 'Review', detail: 'rust-code-reviewer, software-architect and ui-ux-designer in parallel' },
    { title: 'Fix', detail: 'one agent fixes the reported issues and re-runs the checks' },
  ],
}

// args (all optional):
//   scope     what to review, in words or as a git range. Default: all uncommitted changes.
//   maxRounds review rounds before giving up. Default 6.
const input = args && typeof args === 'object' ? args : {}
const scope = input.scope ||
  'all uncommitted changes in the working tree: `git status --short`, `git diff HEAD`, and the untracked files it lists'
const maxRounds = Number.isInteger(input.maxRounds) && input.maxRounds > 0 ? input.maxRounds : 6

const REVIEWERS = [
  { type: 'rust-code-reviewer', label: 'Rust code reviewer' },
  { type: 'software-architect', label: 'Software architect' },
  { type: 'ui-ux-designer', label: 'UI/UX designer' },
]

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    issues: {
      type: 'array',
      description: 'Problems that must be fixed. Empty when there are none.',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['bug', 'risk', 'defect'] },
          file: { type: 'string' },
          line: { type: 'integer' },
          title: { type: 'string' },
          detail: { type: 'string', description: 'What is wrong and a concrete way to trigger or see it' },
          fix: { type: 'string', description: 'The change you recommend' },
        },
        required: ['severity', 'file', 'title', 'detail', 'fix'],
      },
    },
    notes: {
      type: 'array',
      description: 'Optional observations that do not need a change (nits, ideas). Never blocks.',
      items: { type: 'string' },
    },
    reviewed: { type: 'string', description: 'What you looked at and what you ran' },
    notReviewed: { type: 'string', description: 'Anything in scope you could not review, and why' },
  },
  required: ['issues', 'reviewed'],
}

const FIX_SCHEMA = {
  type: 'object',
  properties: {
    fixed: {
      type: 'array',
      items: {
        type: 'object',
        properties: { title: { type: 'string' }, change: { type: 'string' } },
        required: ['title', 'change'],
      },
    },
    declined: {
      type: 'array',
      description: 'Issues deliberately not changed, each with the reason',
      items: {
        type: 'object',
        properties: { title: { type: 'string' }, reason: { type: 'string' } },
        required: ['title', 'reason'],
      },
    },
    checks: { type: 'string', description: 'Result of cargo fmt, clippy and cargo test after the fixes' },
  },
  required: ['fixed', 'declined', 'checks'],
}

function reviewPrompt(reviewer, round, declined) {
  const history = declined.length
    ? `\n\nEarlier rounds deliberately declined these, with reasons. Raise one again only if the reason is wrong, and say why:\n${declined
        .map(d => `- ${d.title}: ${d.reason}`)
        .join('\n')}`
    : ''
  return (
    `Review round ${round}. Scope: ${scope}.\n\n` +
    `Review it from your role (${reviewer.label}). Report under "issues" only problems that need a change before this can ship: ` +
    `bugs, risks on untrusted input or of file corruption, violations of the architecture, and real usability defects. ` +
    `Give the file, the line when you can, a concrete trigger, and the fix. Put nits and ideas under "notes"; they do not block. ` +
    `If you find nothing that needs a change, return an empty "issues" list; do not invent findings. ` +
    `Do not edit any file. If nothing in scope concerns your role, say so in "reviewed" and return no issues.` +
    history
  )
}

// A reviewer defined in .claude/agents is used by type; if the registry does
// not know it (for example the definitions were added in this session), a
// default agent reads the definition and takes the role.
async function review(reviewer, round, declined) {
  const prompt = reviewPrompt(reviewer, round, declined)
  const opts = { label: `${reviewer.label} (round ${round})`, phase: 'Review', schema: REVIEW_SCHEMA }
  let result = null
  try {
    result = await agent(prompt, { ...opts, agentType: reviewer.type })
  } catch (e) {
    log(`${reviewer.label}: agent type not available (${String(e).slice(0, 80)}), using its definition file instead`)
  }
  if (!result) {
    result = await agent(
      `First read .claude/agents/${reviewer.type}.md and act strictly as the agent it defines.\n\n${prompt}`,
      opts,
    )
  }
  return result ? { reviewer: reviewer.label, ...result } : null
}

const declined = []
const history = []
let clean = false
let round = 0

while (round < maxRounds && !clean) {
  round++
  phase('Review')
  const reviews = (await parallel(REVIEWERS.map(r => () => review(r, round, declined)))).filter(Boolean)
  const missing = REVIEWERS.length - reviews.length
  const issues = reviews.flatMap(r => (r.issues || []).map(i => ({ ...i, reviewer: r.reviewer })))
  history.push({
    round,
    issues,
    notes: reviews.flatMap(r => (r.notes || []).map(n => `${r.reviewer}: ${n}`)),
    reviewed: reviews.map(r => `${r.reviewer}: ${r.reviewed}`),
    notReviewed: reviews.filter(r => r.notReviewed).map(r => `${r.reviewer}: ${r.notReviewed}`),
  })
  log(`Round ${round}: ${issues.length} issue(s) from ${reviews.length} reviewer(s)`)
  if (missing > 0) {
    // A reviewer that did not answer has not approved anything.
    log(`Round ${round}: ${missing} reviewer(s) returned nothing; the round does not count as clean`)
    continue
  }
  if (issues.length === 0) {
    clean = true
    break
  }
  if (round === maxRounds) break

  phase('Fix')
  const list = issues
    .map(
      (i, n) =>
        `${n + 1}. [${i.reviewer}, ${i.severity}] ${i.file}${i.line ? ':' + i.line : ''} - ${i.title}\n   ${i.detail}\n   Suggested fix: ${i.fix}`,
    )
    .join('\n')
  const fix = await agent(
    `Fix the review findings below in this repository. Verify each one against the code first: fix what is real, ` +
      `and decline with a specific reason what is wrong or out of scope. Keep the changes minimal and in the style of ` +
      `the surrounding code; add or adjust a test when behaviour changes. Then run \`cargo fmt\`, ` +
      `\`cargo clippy --all-targets --all-features -- -D warnings\` and \`cargo test\`, and make them pass. ` +
      `Do not commit.\n\nFindings:\n${list}`,
    { label: `Fix round ${round}`, phase: 'Fix', schema: FIX_SCHEMA },
  )
  if (!fix) {
    log(`Round ${round}: the fix agent returned nothing; stopping`)
    break
  }
  history[history.length - 1].fix = fix
  declined.push(...(fix.declined || []))
  log(`Round ${round}: ${fix.fixed.length} fixed, ${fix.declined.length} declined. Checks: ${fix.checks.slice(0, 120)}`)
}

if (!clean) {
  log(`Stopped after ${round} round(s) without a clean review; open issues are in the result`)
}

return {
  clean,
  rounds: round,
  openIssues: clean ? [] : history[history.length - 1].issues,
  declined,
  history,
}
