# ADR-001: Use Python Threading for Parallel Audit Execution Over Sequential Processing

## Status
Accepted

## Date
18-05-2026

## Context
The CSPM toolkit audits multiple AWS services (IAM, S3, VPC, EC2, DynamoDB, CloudTrail). Each audit module makes independent Boto3 API calls with no shared state between services. Two execution models were considered: sequential execution of each service audit, or concurrent execution using Python's threading capabilities.

## Decision
Python's threading module is used to execute service audit modules concurrently. Boto3 clients are instantiated per-thread using thread-safe wrapper functions in shared/aws_clients.py.

## Reasoning
Sequential execution means total audit duration scales linearly with the number of services. In large AWS environments with many resources per service, this produces unacceptably slow runtimes. Since audit modules are I/O-bound (waiting on AWS API responses) rather than CPU-bound, threading provides meaningful parallelism without the overhead of multiprocessing. Thread-safe Boto3 client instantiation ensures there are no race conditions across concurrent audits.

## Consequences
Audit runtime is substantially reduced in environments with multiple services under assessment. The thread-safe client wrapper in shared/aws_clients.py must be used consistently across all modules — direct Boto3 client instantiation outside this wrapper is an anti-pattern in this codebase. Adding new service modules automatically benefits from parallel execution without additional configuration.

---