<!-- SPDX-License-Identifier: BUSL-1.1 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->

# ARSIA Protocol SDK Individual Contributor License Agreement

**Version:** 1.0
**Date:** 2026-05-12
**Project:** ARSIA Protocol SDK (`arsialabs/arsia-protocol-sdk`)
**Project License:** Business Source License 1.1, with future conversion to MPL-2.0

## Purpose

This Individual Contributor License Agreement (the "Agreement") defines the terms under which contributions are accepted into the ARSIA Protocol SDK project.

This Agreement grants Arsia Labs (Arsia Tecnologia Unipessoal Lda) and recipients of the Project licenses to use, reproduce, modify, distribute, sublicense, commercially license, and otherwise exploit Your Contributions as part of the Project.

**This Agreement is a license grant, not a copyright assignment.** You retain ownership of Your Contributions.

## 1. Definitions

**"You"** or **"Contributor"** means the individual who submits a Contribution to the Project.

If You are submitting a Contribution on behalf of an employer, client, contractor, institution, or other legal entity, "You" includes that entity, and You represent that You are authorized to bind that entity to this Agreement.

**"Contribution"** means any work of authorship, invention, improvement, modification, documentation, code, configuration, test, example, or other material intentionally submitted by You to the Project for inclusion in, or documentation of, the Project.

"Submitted" means any form of electronic, verbal, or written communication sent to the Project or its Maintainers, including pull requests, commits, patches, issue comments, discussions, mailing lists, source control systems, or other project communication channels, except any communication conspicuously marked or otherwise designated in writing by You as **"Not a Contribution."**

**"Project"** means the ARSIA Protocol SDK repository located at:

`https://github.com/arsialabs/arsia-protocol-sdk`

and any successor location, together with related ARSIA Protocol SDK materials maintained by Arsia Labs under the ARSIA Protocol name.

**"Arsia Labs"** means Arsia Tecnologia Unipessoal Lda, a Portuguese company, and its successors and assigns.

**"Maintainer"** means any individual authorized by Arsia Labs to review, accept, reject, modify, or merge Contributions to the Project.

**"Project License"** means the license applicable to the Project, as described in [LICENSE.md](LICENSE.md):

- Business Source License 1.1 (BUSL-1.1) for all files outside the `shared/` directory, including SDK source code, tests, documentation, conformance runner, build configuration, and automation code;
- Mozilla Public License Version 2.0 (MPL-2.0), without the Exhibit B "Incompatible With Secondary Licenses" notice, after the applicable Change Date for software covered by BUSL-1.1.

The `shared/` directory contains technical interoperability artifacts and specification reference materials mirrored from the ARSIA Protocol specification repository under Apache License 2.0 and CC BY-SA 4.0 respectively. Contributions to `shared/` are not accepted in this repository. See [Section 2.2](#22-the-shared-directory).

## 2. Project Licensing Structure

You understand and agree that Contributions are incorporated into the Project and licensed under the Project License.

### 2.1 SDK Contributions

All Contributions to the ARSIA Protocol SDK are licensed under the Business Source License 1.1.

This includes, without limitation:

- `python/src/` — SDK source code
- `python/tests/` — test suites
- `python/docs/` — Python-specific documentation
- `conformance/` — conformance runner and suites
- `docs/` — cross-language documentation
- build configuration, scripts, and automation code
- documentation files outside `shared/`

You understand that Contributions licensed under Business Source License 1.1 may later convert to Mozilla Public License Version 2.0 (MPL-2.0), without the Exhibit B "Incompatible With Secondary Licenses" notice, after the applicable Change Date.

### 2.2 The `shared/` Directory

The `shared/` directory contains technical interoperability artifacts (schemas, profiles, test vectors) licensed under Apache License 2.0 and specification reference materials (RTMs) licensed under CC BY-SA 4.0. These files are mirrored from the [ARSIA Protocol specification repository](https://github.com/arsialabs/arsia-protocol).

**Contributions to files under `shared/` are not accepted in this repository.** Changes to schemas, profiles, test vectors, RTMs, or other specification artifacts must be submitted to the specification repository under its own contributor license agreement.

## 3. Grant of Copyright License

Subject to the terms of this Agreement, You hereby grant to Arsia Labs and to recipients of the Project a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, distribute, make available, and otherwise use Your Contributions and derivative works thereof.

This license includes the right for Arsia Labs to license, sublicense, distribute, and make Your Contributions available under:

1. the Project License;
2. any successor, replacement, or later version of the Project License adopted by Arsia Labs for the Project;
3. commercial, proprietary, dual-license, or other licensing terms offered by Arsia Labs.

This grant does not transfer ownership of Your Contribution. You remain the copyright owner. You may use, license, or distribute Your Contribution outside the Project on any terms You choose.

## 4. Grant of Patent License

Subject to the terms of this Agreement, You hereby grant to Arsia Labs and to recipients of the Project a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer Your Contributions.

This patent license applies only to patent claims that are licensable by You and that are necessarily infringed by Your Contribution alone or by combination of Your Contribution with the Project to which the Contribution was submitted.

If any entity institutes patent litigation, including a cross-claim or counterclaim in a lawsuit, against You, Arsia Labs, any recipient of the Project, or any other entity alleging that Your Contribution or the Project constitutes direct or contributory patent infringement, then any patent licenses granted to that entity under this Agreement for that Contribution or Project shall terminate as of the date such litigation is filed.

## 5. Relicensing and Commercial Licensing

You understand and agree that Arsia Labs may use Contributions as part of a project that includes:

- publicly available licenses;
- source-available licenses;
- eventually open source licensing;
- commercial licensing;
- proprietary licensing;
- dual licensing;
- sublicensing to customers, partners, affiliates, successors, and assigns.

For the avoidance of doubt, You grant Arsia Labs the right to include Your Contributions in versions of the Project distributed under commercial or proprietary license terms, as well as under the public Project License.

This Agreement does not require Arsia Labs to make any particular version of the Project available under any particular license, except as stated in the applicable license files for the Project.

## 6. Representations

You represent that:

1. **Legal authority.** You are legally entitled to grant the licenses set out in this Agreement. If Your employer, client, contractor, institution, or another legal entity has rights to intellectual property that You create, You have received permission to make the Contribution and grant the licenses in this Agreement, or that entity has waived such rights for Your Contributions to the Project.

2. **Original work or authorized submission.** Each of Your Contributions is Your original creation, or You have the right to submit it under the terms of this Agreement.

3. **Third-party materials.** You will identify the source and applicable license of any portion of a Contribution that is not Your original creation, to the extent You are aware of them.

4. **No conflicting obligations.** Submission of Your Contribution does not violate any agreement, duty, policy, or obligation You have with any third party.

5. **No intentionally harmful content.** To the best of Your knowledge, Your Contribution does not contain malicious code, intentionally hidden vulnerabilities, or intentionally undisclosed security defects.

6. **As-is basis.** You provide Your Contributions on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.

## 7. No Obligation

Arsia Labs is under no obligation to accept, use, merge, publish, or include any Contribution in the Project.

Maintainers may decline, modify, revert, or remove Contributions at their discretion.

Nothing in this Agreement creates an employment, contractor, partnership, fiduciary, joint venture, or agency relationship between You and Arsia Labs.

## 8. How to Accept This Agreement

You accept this Agreement by adding a `Signed-off-by` line to the commit message of each commit You submit to the Project.

The `Signed-off-by` trailer certifies that You agree to this Agreement and to the Developer Certificate of Origin:

<https://developercertificate.org>

The `git` command-line tool adds this trailer automatically when You use the `-s` or `--signoff` flag:

```bash
git commit -s -m "fix: correct kid prefix validation"
```

This produces a trailer of the form:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email You use must correspond to Your real identity. Pseudonymous contributions cannot be accepted under this Agreement.

A pull request containing commits without a valid `Signed-off-by` trailer will not be merged.

## 9. Corporate Contributions

If You submit a Contribution on behalf of an employer, client, institution, or other legal entity, You represent that You have authority to bind that entity to this Agreement.

Arsia Labs may require a separate corporate contributor license agreement before accepting Contributions from employees, contractors, consultants, or representatives of certain organizations.

## 10. Miscellaneous

This Agreement is governed by the laws of Portugal, without regard to conflict-of-law principles.

If any provision of this Agreement is held unenforceable, the remaining provisions shall remain in full force and effect.

This Agreement constitutes the entire agreement between You and Arsia Labs regarding Your Contributions to the Project and supersedes any prior understandings on the subject.

---

_ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by [Arsia Labs (Arsia Tecnologia Unipessoal Lda)](https://arsialabs.ai)_
