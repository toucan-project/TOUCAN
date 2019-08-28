# TOUCAN
<!-- vim-markdown-toc GitLab -->

* [Prequisities](#prequisities)
* [Installation](#installation)

<!-- vim-markdown-toc -->

## Prequisities
There are two machines required for this to work.

1. Canary machine, with an HTTP server and SMB.
2. Alert machine, has DNS and `syslog-ng` listeners.

The canary machine pushes logs to the alert machine, and in case of an event coming from a canary document,
sends an alert to a predefined user.

It is recommended to use Ubuntu 19.xx as server OS. 

## Installation
[coming soon]
