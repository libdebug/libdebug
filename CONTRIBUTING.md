## Contributing

[fork]: /fork
[pr]: /compare
[style]: https://standardjs.com/
[code-of-conduct]: CODE_OF_CONDUCT.md

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Please note that this project is released with a [Contributor Code of Conduct][code-of-conduct]. By participating in this project you agree to abide by its terms.

## Issues and PRs

If you have suggestions for how this project could be improved, or want to report a bug, open an issue! We'd love all and any contributions. If you have questions, too, we'd love to hear them.

- **Do not open a duplicate issue!** Search through existing issues to see if your issue has previously been reported. If your issue exists, comment with any additional information you have. You may simply note "I have this problem too", which helps prioritize the most common problems and requests. 

- **Prefer using [reactions](https://github.blog/2016-03-10-add-reactions-to-pull-requests-issues-and-comments/)**, not comments, if you simply want to "+1" an existing issue.

We'd also love PRs. If you're thinking of a large PR, we advise opening up an issue first to talk about it, though! Look at the links below if you're not sure how to open a PR.

- **Smaller is better.** Submit **one** pull request per bug fix or feature. A pull request should contain isolated changes pertaining to a single bug fix or feature implementation. **Do not** refactor or reformat code that is unrelated to your change. It is better to **submit many small pull requests** rather than a single large one. Enormous pull requests will take enormous amounts of time to review, or may be rejected altogether. 

- **Add documentation.** Document your changes with code doc comments or in existing guides.

- **[Resolve any merge conflicts](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/resolving-a-merge-conflict-on-github)** that occur.

- **Promptly address any CI failures**. If your pull request fails to build or pass tests, please push another commit to fix it.

- **libdebug values performance**. It is within the core philosophy of libdebug to implement smart solutions to reduce overhead. This is particularly useful for multiple runs of an executable or specificsome debugging strategies.

- When writing comments, use properly constructed sentences, including punctuation.

- **Include test coverage.** Add unit tests or UI tests when possible. Follow existing patterns for implementing tests.

we provide a suite of tests that you can run and add your own to:

```bash
cd test
python run_suite.py
```

The test folder includes the Makefile that was used to build the required binaries for transparency. However, the compiled binaries may differ due to scheduling, hardware, and compiler versions. Some tests have hardcoded absolute addresses and will likely fail as a result. Please do not commit rebuilt versions of existing test binaries.


## Asking Questions

GitHub issues are not the appropriate place to debug your specific project, but should be reserved for filing bugs and feature requests. If you cannot find what you are looking for anywhere, [contact us](https://libdebug.org/).

## Submitting a pull request

1. [Fork][fork] and clone the repository.
1. Configure and install the dependencies:
Ubuntu: `sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`
Debian: `sudo apt install -y python3 python3-dev g++ libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg`<br>
Fedora: `sudo dnf install -y python3 python3-devel kernel-devel g++ binutils-devel libdwarf-devel`<br>
Arch Linux: `sudo pacman -S python libelf libdwarf gcc make debuginfod`<br>
1. Create a new branch: `git checkout -b my-branch-name`
1. Install your package in editable mode: `pip install -e /path/to/your/local/repo`
1. Make your change, add tests, and make sure the tests still pass. Remember, if you change any .c files, you will need to run the command at the previous point **again**.
1. Push to your fork and [submit a pull request][pr].
1. Pat your self on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Follow the [conventional commit format](https://www.conventionalcommits.org/en/v1.0.0/).
- Write and update tests.
- Keep your changes as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

Work in Progress pull requests are also welcome to get feedback early on.

## Coding Style

Consistency is the most important. Following the existing style, formatting, and naming conventions of the file you are modifying and of the overall project. Failure to do so will result in a prolonged review process that has to focus on updating the superficial aspects of your code, rather than improving its functionality and performance.

## Certificate of Origin

*Developer's Certificate of Origin 1.1*

By making a contribution to this project, I certify that:

> 1. The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or
> 1. The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open source license (unless I am permitted to submit under a different license), as indicated in the file; or
> 1. The contribution was provided directly to me by some other person who certified (1), (2) or (3) and I have not modified it.
> 1. The contribution was licenced under the same terms as the original project (MIT Licence).
> 1. I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

## Resources

- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
- [GitHub Help](https://help.github.com)
