---
name: code-smell-audit
description: >
  Identify, document, and plan remediation of code smells in files, diffs,
  pull requests, and codebases. Covers bloaters, object-orientation abusers,
  change preventers, dispensables, and couplers. Use when asked to review
  code for smells, audit a codebase, review a PR or diff, refactor for
  maintainability, document technical debt, or create refactoring tickets.
  Produces inline review comments, smell audit reports, and refactoring plans.
triggers:
  - code smell
  - code smells
  - review for smells
  - smell audit
  - review this PR
  - review PR
  - review this diff
  - audit code
  - audit codebase
  - refactor
  - refactoring
  - technical debt
  - tech debt
  - code review
  - code quality
license: MIT
metadata:
  author: faizahmedfarooqui
  version: "1.0.0"
---

# Code smells detection and remediation skill

Identify code smells, explain why they matter, and produce actionable refactoring plans that developers can pick up without guesswork. Every smell report must answer: what the smell is, where it lives, why it's harmful, how to fix it, and what the fix unlocks.

The skill applies to any programming language unless the request restricts the scope.

## Assessment rules

### Severity assessment

Every identified smell must be rated:

| Severity | Definition                                                       |
| -------- | ---------------------------------------------------------------- |
| Critical | Actively causing bugs, blocking features, or hiding defects      |
| Major    | Significantly harms readability, testability, or maintainability |
| Minor    | Noticeable friction but manageable with discipline               |
| Trivial  | Cosmetic or stylistic; low impact on day-to-day work             |

### Confidence tagging

When reviewing code without full project context, tag each finding:

- **Definite** — the smell is unambiguous from the code alone
- **Probable** — strong signal but surrounding context could justify the pattern
- **Possible** — worth flagging for the team to evaluate

### Check usage before severity

Before classifying a finding as **Critical** (e.g. security, correctness), verify that the code is **actually used**. Search the codebase for call sites, references, or imports.

- If the code is **dead** (no callers, unreachable, or only referenced in comments/docs), treat **Dead code** as the primary smell. Recommend **removal** as the fix. Note any secondary smell (e.g. hardcoded secret) only as “would matter if this were ever used”.
- If the code **is in use**, then assign severity to the active smell (e.g. Critical for the hardcoded secret) and suggest the appropriate fix (e.g. load secret from config).

This avoids overstating impact (e.g. “Critical: hardcoded secret” for an unused method) and keeps the recommended action accurate (delete vs. refactor).

---

## Smell catalogue

Use these categories when classifying detected smells. Always reference the canonical name so teams build shared vocabulary.

---

### Bloaters

Code that has grown too large to work with comfortably.

#### Long method

A method containing too many lines of code. As a rule of thumb, anything over ~10 lines should raise questions. If you feel the need to add a comment explaining a section inside a method, that section is a candidate for extraction.

**Key signals:**

- Method requires scrolling to read or inline comments to follow
- Multiple levels of nesting (conditionals inside loops inside conditionals)
- Local variables that only serve one section of the method
- "Just two more lines" additions that have accumulated over time

**Treatments:**

- **Extract method** — break the body into separate, focused methods. If a section needs a comment, it should be its own method with a descriptive name.
- **Replace temp with query** — if local variables prevent extraction, replace temporaries with method calls so the code can be split.
- **Introduce parameter object** or **Preserve whole object** — consolidate long parameter lists that have grown alongside the method.
- **Replace method with method object** — if local variable entanglement makes extraction impossible, move the entire method into its own class where locals become fields.
- **Decompose conditional** — conditionals and loops are natural extraction boundaries. Extract each branch into a named method.

#### Large class

A class with many fields, methods, and lines of code that serves multiple responsibilities. Classes tend to start small and bloat over time as developers add features to existing classes rather than creating new ones.

**Key signals:**

- Difficult to summarise the class's purpose in one sentence
- Groups of fields that are only used together by a subset of methods
- Method names that cluster into unrelated groups (e.g., finding, displaying, and ordering)

**Treatments:**

- **Extract class** — spin off a cohesive group of fields and methods into a separate component.
- **Extract subclass** — use when part of the behaviour is used only in specific cases or has variant implementations.
- **Extract interface** — use when you need to define a contract for what clients can use.
- **Duplicate observed data** — for classes mixing GUI and domain logic, separate them into distinct objects, keeping data consistent across both.

#### Primitive obsession

Over-reliance on primitive types (strings, integers, booleans) instead of small value objects for domain concepts like currency, ranges, phone numbers, or type codes.

**Key signals:**

- String or int fields representing domain concepts (e.g., `currency_amount` as a float, `phone` as a string)
- Constants used for type coding (e.g., `USER_ADMIN_ROLE = 1`)
- String constants used as array keys to simulate object fields
- Validation logic for the same primitive scattered across multiple places

**Treatments:**

- **Replace data value with object** — group related primitives into a value object and move associated behaviour into it.
- **Introduce parameter object** or **Preserve whole object** — consolidate primitive parameters that travel together.
- **Replace type code with class**, **Replace type code with subclasses**, or **Replace type code with state/strategy** — replace coded constants with a proper class hierarchy.
- **Replace array with object** — convert arrays with string-keyed fields into typed objects.

#### Long parameter list

More than three or four parameters for a method. Long lists are hard to understand, easy to misorder, and often signal that the method is doing too much or that a missing abstraction is hiding in the parameters.

**Key signals:**

- Method signatures that don't fit on one line
- Boolean parameters that toggle behaviour (often signals the method should be split)
- Parameters extracted from an object only to be passed individually

**Treatments:**

- **Replace parameter with method call** — if the value can be obtained from an object already available inside the method, remove the parameter and query internally.
- **Preserve whole object** — pass the object itself instead of extracting and forwarding its fields.
- **Introduce parameter object** — group unrelated parameters that always travel together into a dedicated object.

**When to ignore:** Don't remove parameters if doing so would create unwanted dependency between classes. Sometimes an explicit parameter list keeps two classes properly decoupled.

#### Data clumps

Identical groups of data (3+ fields or parameters) appearing together repeatedly across the codebase. If you delete one value from the group and the rest stop making sense on their own, you have a data clump.

**Key signals:**

- The same three or four fields in several classes
- The same set of parameters in multiple method signatures
- Copy-pasted data patterns across the codebase without a unifying abstraction

**Treatments:**

- **Extract class** — move the repeating fields into their own dedicated class.
- **Introduce parameter object** — consolidate repeated parameter groups into an object.
- **Preserve whole object** — pass the data object rather than individual fields.
- Once grouped, look for operations on the data that should live in the new class.

**When to ignore:** Passing entire objects instead of primitive values may create unwanted coupling between classes. Weigh the trade-off.

---

### Object-orientation abusers

Incorrect or incomplete application of OO principles.

#### Alternative classes with different interfaces

Two or more classes perform identical functions but expose them through different method names, creating unnecessary confusion and duplicated logic.

**Key signals:**

- Multiple classes with methods that do the same thing but are named differently
- Developers unaware of each other's implementations
- Client code that adapts to whichever class it happens to use

**Treatments:**

- **Rename methods** — align method names across all alternative classes.
- **Move method**, **Add parameter**, **Parameterise method** — make signatures and implementations match.
- **Extract superclass** — if only part of the functionality overlaps, extract the shared portion into a common superclass.
- Once interfaces are unified, delete the redundant class.

**When to ignore:** Merging is impractical when the alternative classes live in different third-party libraries with their own release cycles.

#### Refused bequest

A subclass uses only some of the methods and properties inherited from its parent. Unused methods either sit dormant or are overridden to throw exceptions — a signal that the inheritance hierarchy doesn't reflect a real "is-a" relationship.

**Key signals:**

- Subclass overrides parent methods to throw exceptions or return empty/null
- Large portions of the parent's interface are irrelevant to the subclass
- Inheritance was motivated by code reuse rather than a genuine type relationship

**Treatments:**

- **Replace inheritance with delegation** — eliminate the parent-child relationship entirely. The former subclass holds a reference to the former superclass and delegates only the calls it needs.
- **Extract superclass** — if inheritance is justified but messy, pull genuinely shared members into a new, purpose-built superclass.

#### Switch statements

Complex `switch` or long `if/else if` chains that dispatch on a type code. The issue isn't a single `switch` — it's that when you add a new type, you must find and update _every_ switch that dispatches on that code.

**Key signals:**

- `switch` or `if/else if` chains that branch on the same type code in multiple places
- Adding a new variant requires editing multiple files
- Cases that perform structurally similar operations with minor differences

**Treatments:**

- **Extract method + Move method** — isolate the switch, then move it to the class where polymorphism is needed.
- **Replace type code with subclasses** or **Replace type code with state/strategy** — set up a class hierarchy or strategy objects.
- **Replace conditional with polymorphism** — let method overriding handle the branching.
- **Replace parameter with explicit methods** — if each branch calls the same method with a different parameter, create separate intention-revealing methods.
- **Introduce null object** — if one branch checks for `null`, eliminate that check with a null object.

**When to ignore:**

- A simple `switch` that maps values to straightforward actions and is unlikely to grow.
- `switch` inside Factory patterns (Abstract Factory, Factory Method) is a common and acceptable idiom.

#### Temporary field

Fields that only get their values under certain conditions and are empty the rest of the time. You expect an object's fields to carry meaningful data at all times — temporaries violate that expectation.

**Key signals:**

- Fields set only within one algorithm or method, empty otherwise
- Null checks around fields that should always have values
- Fields created to avoid passing many parameters to a single method

**Treatments:**

- **Extract class** — move the temporary fields and all code that operates on them into a separate class (effectively a method object).
- **Introduce null object** — if conditionals check whether temporary fields have values, replace them with a null object providing sensible defaults.

---

### Change preventers

Smells that force shotgun edits across the codebase whenever something changes.

#### Divergent change

A single class must be modified for many unrelated reasons. When adding a new product type requires changing the same class's finding, displaying, _and_ ordering methods, that class has too many responsibilities.

**Key signals:**

- Unrelated changes keep landing in the same class
- The class is a frequent merge conflict hotspot
- You can describe the class's responsibilities only as a list of unrelated concerns

**Treatments:**

- **Extract class** — split the class so each resulting class is responsible for one cohesive set of changes.
- **Extract superclass** or **Extract subclass** — if different classes share some behaviour, combine through inheritance.

_Note: Divergent change is the opposite of Shotgun Surgery. Divergent change = many reasons to change one class. Shotgun surgery = one reason to change many classes._

#### Shotgun surgery

A single logical change requires many small edits across many different classes. A responsibility has been split too thin.

**Key signals:**

- A small feature change or bug fix touches 5+ files
- The same kind of edit (e.g., adding a field) must be repeated in several places
- Can result from overzealous application of Extract Class

**Treatments:**

- **Move method** and **Move field** — consolidate the scattered responsibility into a single class. Create a new class if no existing one fits.
- **Inline class** — if moving code leaves original classes nearly empty, absorb them.

#### Parallel inheritance hierarchies

A special case of Shotgun Surgery: every time you create a subclass for one class, you must create a matching subclass for another class.

**Key signals:**

- Two hierarchies that grow in lockstep
- Class prefixes or suffixes that mirror each other across hierarchies
- Adding a variant means touching two separate inheritance trees

**Treatments:**

- **Move method** and **Move field** — make instances of one hierarchy reference instances of the other, then eliminate the duplicate hierarchy by relocating its functionality.

**When to ignore:** Sometimes parallel hierarchies are the lesser evil. If de-duplicating them produces code that is uglier and harder to maintain, revert and accept the duplication.

---

### Dispensables

Things whose removal would make the code cleaner.

#### Comments (deodorant)

Comments that explain _what_ code does rather than _why_. When code needs a comment to be understood, the code itself should be restructured. The best comment is a good method or variable name.

**Key signals:**

- Inline comments narrating each step of a method
- Block comments acting as section headers inside a method body
- Comments that restate what the code literally does

**Treatments:**

- **Extract variable** — when a comment explains a complex expression, split it into named subexpressions.
- **Extract method** — when a comment explains a section of code, convert that section into a method. The comment text often becomes the method name.
- **Rename method** — if a method still needs comments after extraction, give it a more self-explanatory name.
- **Introduce assertion** — replace comments about required system state with executable assertions.

**When to ignore:**

- Comments explaining _why_ something is implemented a particular way (business rules, workarounds, non-obvious constraints).
- Comments explaining complex algorithms after other simplification methods have been exhausted.

#### Duplicate code

Two or more code fragments that are near-identical. Duplication means every bug fix or behaviour change must be applied in multiple places — and one will inevitably be missed.

**Key signals:**

- Copy-pasted blocks with minor variations
- Structurally different code that performs identical logic
- Similar methods across sibling classes

**Treatments:**

- **Same class** — Extract method, then call it from both locations.
- **Sibling classes** — Extract method in both, then Pull up field / Pull up constructor body for shared parts. Use Form template method for similar-but-not-identical logic. Use Substitute algorithm when two methods do the same thing differently.
- **Unrelated classes** — Extract superclass if a hierarchy makes sense; otherwise Extract class and reference it from both.
- **Conditional duplication** — Consolidate conditional expressions, then Extract method. Move identical code outside conditional branches.

#### Data class

A class that contains only fields and crude getters/setters with no behaviour. It's a data container that other classes operate on — the class itself can't do anything with its own data.

**Key signals:**

- Class has fields, getters, setters, and nothing else
- All logic operating on the class's data lives in other classes
- The class is passed around as a dumb struct

**Treatments:**

- **Encapsulate field** / **Encapsulate collection** — hide public fields behind proper accessors.
- **Move method** / **Extract method** — migrate behaviour from client code into the data class itself.
- **Remove setting method** — once the class has behaviour, eliminate overly permissive setters.
- **Hide method** — make getters and setters that are only used internally non-public.

#### Dead code

Variables, parameters, fields, methods, or classes that are no longer used. They add noise, slow comprehension, and create false leads during debugging.

**Key signals:**

- IDE or linter warnings about unused symbols
- Methods only called from other dead code
- Conditional branches that are unreachable due to logic changes

**Treatments:**

- **Delete it** — use IDE dead-code detection to find and remove unused code.
- **Inline class** — when a class no longer serves a purpose.
- **Collapse hierarchy** — when a subclass or superclass in an inheritance tree is unused.
- **Remove parameter** — eliminate unneeded method parameters.

#### Lazy class

A class that doesn't do enough to justify the cognitive cost of its existence. Every class costs time to understand and maintain — it must earn that cost.

**Key signals:**

- Class with one or two trivial methods
- Class that was gutted by refactoring and never consolidated
- Class created for future use that never materialised

**Treatments:**

- **Inline class** — absorb the class into wherever it's used.
- **Collapse hierarchy** — merge a thin subclass into its parent.

#### Speculative generality

Abstractions, hooks, parameters, or classes created "just in case" for future features that never arrived. The code is harder to understand and maintain for no current benefit.

**Key signals:**

- Abstract classes with only one concrete implementation
- Unused method parameters or fields
- Methods that only delegate without adding value
- Class names with "Base", "Abstract", or "Generic" that serve no polymorphic purpose

**Treatments:**

- **Collapse hierarchy** — remove unnecessary abstract classes.
- **Inline class** — eliminate unnecessary delegation.
- **Inline method** — fold unused indirection back into callers.
- **Remove parameter** — strip unused parameters.
- **Delete unused fields** directly.

**When to ignore:**

- Framework code where extensibility is the explicit purpose, even if the framework itself doesn't use it.
- Test infrastructure that accesses class internals for verification.

---

### Couplers

Smells that create excessive coupling between classes.

#### Feature envy

A method that accesses another object's data more than its own. The method is in the wrong class — it belongs with the data it's most interested in.

**Key signals:**

- Method makes many getter calls on another object
- Method barely touches its own class's fields
- Often emerges after fields are moved to a data class without moving the operations too

**Treatments:**

- **Move method** — transfer the entire method to the class whose data it uses most.
- **Extract method** — if only part of the method is envious, extract that part and move it.
- For methods that access multiple classes, place the method with the class that holds the most accessed data, or split it.

**When to ignore:** Intentional separation of behaviour from data is appropriate in Strategy and Visitor patterns, where the design deliberately decouples algorithm from data structure.

#### Inappropriate intimacy

A class reaches into the internal fields and methods of another class rather than interacting through a well-defined interface. The two classes become tightly coupled and hard to change independently.

**Key signals:**

- Direct access to another class's private or protected members
- Bidirectional dependencies between two classes
- Changes to one class's internals routinely break the other

**Treatments:**

- **Move method** and **Move field** — transfer components to the class that actually uses them.
- **Extract class** and **Hide delegate** — formalise the relationship through a dedicated class with a clean interface.
- **Change bidirectional association to unidirectional** — simplify mutual dependencies to one-way.
- **Replace delegation with inheritance** — when the relationship genuinely is an "is-a", inheritance can replace intimate delegation.

#### Message chains

A client navigates through a chain of objects to reach the one it actually needs: `a.b().c().d()`. The client is coupled to the entire navigation structure — any change to intermediate objects breaks it.

**Key signals:**

- Chains of sequential method calls or property accesses
- Client code that "knows" the internal structure of multiple objects
- Intermediate objects exist only to provide navigation

**Treatments:**

- **Hide delegate** — introduce a delegate method so the client doesn't need to know about intermediate objects.
- **Extract method + Move method** — understand why the final object is accessed, then relocate that logic to the beginning of the chain.

**When to ignore:** Overly aggressive delegate hiding can obscure where functionality lives, introducing a Middle Man smell instead. Flatten only as far as is genuinely helpful.

#### Middle man

A class that exists only to forward calls to another class without adding any meaningful behaviour. It's an empty shell.

**Key signals:**

- Most or all methods simply delegate to another class
- The class adds no logic, transformation, or coordination
- Often results from over-correcting Message Chains

**Treatments:**

- **Remove middle man** — let clients interact directly with the actual working class.

**When to ignore:**

- The middle man prevents direct interclass dependencies that would be worse.
- The class intentionally implements Proxy, Decorator, or Facade patterns.

#### Incomplete library class

A library no longer meets your needs and modifying it directly isn't an option. You find yourself working around limitations rather than extending cleanly.

**Key signals:**

- Utility methods scattered across your codebase that "fix" library gaps
- Wrapper classes that exist only to add one or two missing methods
- Repeated workarounds for the same library limitation

**Treatments:**

- **Introduce foreign method** — for adding a small number of methods to a library class.
- **Introduce local extension** — for more substantial modifications, create a subclass or wrapper.

**When to ignore:** Extending a library can generate maintenance overhead if modifications ripple through your codebase. Weigh extension cost against building a custom solution.

---

## Output types

### Type 1: Smell audit report

Use when reviewing a file, module, or codebase for smells. This is the default output when a user says "review for code smells", "audit this code", or "find smells".

#### Template

```markdown
# Code smell audit: [file/module/component name]

**Reviewed:** [date]
**Scope:** [files or directories reviewed]
**Total smells found:** [count by severity — e.g., 2 critical, 3 major, 1 minor]

---

## Critical

### 1. [Smell name] — [location]

- **Category:** [Bloater / OO abuser / Change preventer / Dispensable / Coupler]
- **Confidence:** [Definite / Probable / Possible]
- **Lines:** [file:line_start–line_end or description of location]
- **What:** [1–2 sentences describing the smell in context]
- **Why it matters:** [Concrete impact — bugs, duplication, friction, coupling]
- **Suggested fix:** [Specific refactoring technique with enough detail to act on]
- **Effort estimate:** [S / M / L]

---

## Major

### 2. [Smell name] — [location]

...

---

## Minor

...

---

## Summary

[2–3 sentences: overall code health, top priorities, recommended order of attack]
```

#### Rules for smell audit reports

- Group findings by severity, not by category
- Every finding must include a concrete suggested fix, not just the smell name
- Reference specific lines or symbols — never say "somewhere in the file"
- If a smell is intentional or justified, note it under a **"When to ignore"** callout
- Include an effort estimate (S/M/L) so teams can plan
- The summary must recommend a starting point — don't leave the reader with a flat list

---

### Type 2: Refactoring ticket

Use when the user asks to turn a smell into a ticket, task, or backlog item. Follow the template below, and align fields/naming with your team's issue tracker conventions.

#### Template

```markdown
**Title:** [Verb] [component] to resolve [smell name] (sentence case, < 100 chars)

## Context

[2–3 sentences: what the smell is, where it lives, why fixing it matters now. Link to audit if available.]

## Current state

[Brief description or code snippet showing the smell]

## Desired state

[Brief description or code snippet showing the target after refactoring]

## Technical approach

[Step-by-step refactoring plan — specific enough to scope, flexible enough for implementation decisions]

1. [First refactoring step]
2. [Second step]
3. [Verification step]

## Acceptance criteria

- [ ] [Specific, testable outcome]
- [ ] [Verification that the smell is resolved]
- [ ] No regressions in [related functionality]
- [ ] Unit/integration tests updated
- [ ] Documentation updated if public API changes

## Affected systems

- [List files, modules, or services impacted]

## Rollback plan

[How to revert if something goes wrong]

## Dependencies

- **Blocked by:** [PROJ-XXX] if applicable
- **Blocks:** [PROJ-YYY] if applicable

## Smell metadata

- **Category:** [Bloater / OO abuser / Change preventer / Dispensable / Coupler]
- **Severity:** [Critical / Major / Minor / Trivial]
- **Effort:** [S / M / L]
```

#### Rules for refactoring tickets

- Title must pass the completion test: "To complete this ticket, I need to [TITLE]"
- Always include current state vs desired state — make the change visible
- The technical approach describes scope, not a rigid implementation prescription
- Acceptance criteria must verify the smell is gone, not just that code was changed
- Include rollback plan for any structural changes

---

### Type 3: Inline code review comments

Use when the user asks for review-style comments on a specific file or diff. Output as a list of comments anchored to lines.

#### Template

```
**[file:line]** — [Smell name] ([severity])
[1–2 sentence explanation + suggested fix]
```

#### Example

```
**src/billing/invoice.py:42–87** — Long method (major)
`generate_invoice` is 45 lines with three nested conditionals. Extract the tax calculation (lines 55–72) into a `calculate_tax` method and the discount logic (lines 73–85) into `apply_discounts`.

**src/billing/invoice.py:12–18** — Data clump (minor)
`customer_name`, `customer_email`, and `customer_id` appear together here and in `receipt.py`. Consider introducing a `CustomerRef` value object.
```

#### Rules for inline comments

- Anchor every comment to a file and line range
- Keep each comment to 1–3 sentences — dense and actionable
- Suggest the specific refactoring, not just the smell name
- Order by severity, then by line number within each severity

---

## Workflow guidance

### When the user says "review this for code smells"

1. Read the file(s) or diff provided
2. Scan systematically through each smell category
3. Produce a **smell audit report** (Type 1)
4. If asked, convert critical/major findings into **refactoring tickets** (Type 2)

### When the user says "refactor this" or "fix this smell"

1. Identify the specific smell(s) present
2. Explain the smell and why it matters (briefly)
3. Perform or propose the refactoring
4. Verify the smell is resolved in the result

### When the user provides a diff or PR for review

1. Focus on **inline code review comments** (Type 3)
2. Only flag smells introduced or worsened by the diff — don't audit the entire file unless asked
3. Acknowledge pre-existing smells separately if they're relevant

When reviewing a diff or PR, focus primarily on smells introduced or worsened by the changes.
Pre-existing smells should only be mentioned when they interact with the new changes.

### Prioritisation guidance

When multiple smells are found, recommend fixing in this order:

1. **Change preventers** first — they make all other fixes harder
2. **Couplers** next — they spread the blast radius of changes
3. **Bloaters** — they hide other smells inside them
4. **Dispensables** — quick wins that reduce noise
5. **Object Orientation abusers** — often need the most design thought

---

## Anti-patterns to avoid

1. **The label-only review** — naming a smell without explaining impact or suggesting a fix. Every finding needs a "why it matters" and a "suggested fix".
2. **The false positive flood** — flagging every method over 10 lines as a Long Method without considering context. Use the confidence tag and apply judgement.
3. **The architecture astronaut** — recommending a full redesign when a targeted extract-method would suffice. Match the fix to the severity.
4. **The missing trade-off** — not acknowledging when a smell is intentional (e.g., a Middle Man implementing the Proxy pattern). Use "When to ignore" callouts.
5. **The orphan finding** — reporting a smell with no connection to real impact. Always tie the smell to a concrete consequence: bugs, duplication, coupling, or friction.
6. **Critical severity for dead code** — flagging code as Critical (e.g. security) without checking whether it is called or reachable. If the symbol has no call sites, treat it as Dead code, recommend removal, and only mention the secondary smell as a “if ever used” caveat.

---

## Output destination

### CI / GitHub Actions (automated PR review)

When running inside a GitHub Actions workflow (detected by the presence of `GITHUB_ACTIONS=true` in the environment, or when the invocation context is a pull request review):

- **Do not save files.** Post all findings directly as GitHub PR review comments.
- Use **inline comments** (Type 3) anchored to the exact file and line where each smell lives.
- Roll up trivial findings into a single top-level PR comment rather than posting them inline.
- End with a **summary PR comment** covering: overall assessment, severity distribution (e.g. "0 critical, 2 major, 1 minor"), and the recommended starting point.
- Do not post findings already caught by existing CI checks (linters, type checkers, test failures).

### Local / interactive session

Save generated reports and tickets as markdown files.

- Create the output directory if it doesn't exist
- **Audit reports:** `code-smell-audit-{component-slug}.md` (e.g., `code-smell-audit-billing-module.md`)
- **Refactoring tickets:** Follow the JIRA ticket naming convention if available, otherwise `refactor-{smell-slug}-{component-slug}.md` (e.g., `refactor-long-method-invoice-generator.md`)
- After saving, tell the user the file path

---

## Asking for input

When the user's request is ambiguous, ask about:

1. **Scope** — which files, modules, or directories to review?
2. **Depth** — full audit, quick scan, or focused on a specific smell category?
3. **Output type** — audit report, refactoring tickets, or inline comments?
4. **Context** — is this greenfield, legacy, or actively maintained? This affects severity assessment.
5. **Priorities** — are there known pain points or areas the team already struggles with?
