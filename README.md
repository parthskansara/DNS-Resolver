# DomainHunter: DNS Resolver

## Table of Contents:
* [Introduction](#introduction)
* [Libraries used](#libraries-used)
* [Run the project](#run-the-project)
* [Performance](#performance)
* [Reference](#reference)

## Introduction:
Almost everything on the Internet involves DNS resolution. If DNS is slow, the
performance of your application is going to suffer.

In this project, we write our own DNS resolver, and compare its performance with other existing DNS resolvers. It also includes a *dig tool* and a *DNSSEC resolver*.

## Libraries used
* [dnspython](https://pypi.org/project/dnspython/)

## Run the project

From the command line, run:


```bash
# Clone this repository
$ git clone https://github.com/parthskansara/DNS-Resolver

# Go into the repository
$ cd DNS-Resolver

# Install dependencies
$ pip install -r requirements.txt

# Run the DNS Resolver
# Eg: python dns-resolver.py google.com A
$ python dns-resolver.py [domain-name] [request-type]

# Run the DNSSEC Resolver
# Eg: python dnssec-resolver.py verisigninc.com
$ python dnssec-resolver.py [domain-name]

```
* For a detailed explanation of the DNSSEC resolver, check [this](https://github.com/parthskansara/DNS-Resolver/blob/main/DNSSEC%20Implementation.pdf).


## Performance
Check out the performance comparison of this DNS resolver against the local DNS resolver and Google's public DNS [here](https://github.com/parthskansara/DNS-Resolver/blob/main/compare.pdf)!

## Reference
This project was completed as a part of the course CSE 534: Fundamentals of Computer Vision (Fall 2022) under [Prof. Aruna Balasubramanian](https://www.cs.stonybrook.edu/people/faculty/ArunaBalasubramanian) at Stony Brook University.


The original assignment can be found [here](https://drive.google.com/file/d/1_DbFCx03tswdxjzVQf_-hGMb6fFczmvz/view?usp=sharing).
