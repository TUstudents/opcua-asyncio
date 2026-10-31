# Changelog

## 3.0.0 (unreleased)

The first release of `enginir-opcua`, a fork of [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0.
All breaking changes are collected here and released together.

### Migrating from asyncua 2.x

Package and identity:
- The import package is `enginir_opcua` and the distribution is `enginir-opcua`. There is no `asyncua` alias, so both
  packages can be installed side by side.
- The command line is one program, `enginir-opcua`, with the subcommands `read`, `write`, `call`, `ls`, `subscribe`,
  `history`, `discover`, `server`, `shell` and `generate-structs`. The scripts `enginir-uaread`, `enginir-uals`,
  `enginir-uaserver` and the others stay as deprecated aliases that print a notice; they are removed in 4.0.0.
- The default application identity changed: server endpoint `opc.tcp://0.0.0.0:4840/enginir-opcua/server/`,
  ApplicationUri `urn:enginir:opcua:server` and `urn:enginir:opcua:client`, ProductUri `urn:enginir:opcua`,
  ManufacturerName `engiNIR`.
- Python 3.12 or newer is required.
- There are no optional extras: the `profile` extra is gone, and `pytest-profiling` is in the `dev` group.

Security:
- RegisterServer and RegisterServer2 answer `Bad_ServiceUnsupported` unless the server calls
  `Server.accept_server_registrations()`. When enabled, a registration needs a secure channel whose certificate
  carries the ServerUri; empty ServerNames give `Bad_ServerNameMissing`, `IsOnline = false` removes the entry, the
  registry holds at most 100 servers and entries expire after 10 minutes.

Secure defaults and certificate trust (OPC 10000-4, 6.1.3):
- One `CertificateValidator(trust_store, suppress=..., check_revocation=..., accept_ca_application_certificates=...)`
  runs the validation steps in the spec's order (chain, signature, security policy, trust, validity, host name, URI,
  usage, revocation). It replaces the flag-based `CertificateValidator`/`CertificateValidatorOptions`.
- It runs at every OpenSecureChannel and renewal, on both server and client. Both sides trust nothing until
  `Server.set_trust_store()` / `Client.set_trust_store()` is called. A server certificate passed to
  `Client.set_security()` is pinned; one fetched over an unsecured GetEndpoints isn't trusted.
- A PKI directory (`own/`, `trusted/`, `issuer/` with `crl/` folders, `rejected/`) configures the certificate, the key and
  the trust in one call: `Server.set_pki_directory()`, `Client.set_pki_directory()`, `Server.set_user_pki_directory()`.
  A peer certificate that fails validation is kept in `rejected/certs` (never trusted); `Server.reload_trust_store()`
  picks up files moved to `trusted/certs`.
- The server tells a peer only `Bad_SecurityChecksFailed` and logs the detail; the client raises the detailed code.
- Certificates are checked for expiry, key usage, key length and signature hash per security policy, the host name
  (client side) and the ApplicationUri. A ClientDescription ApplicationUri that isn't in the client certificate gives
  `Bad_CertificateUriInvalid`. The certificates committed under `examples/` fail these checks; the examples now
  generate their own.
- `Server.set_certificate_validator(hook)` and `Client.certificate_validator` are now `set_application_hook()` /
  `application_hook`; `set_certificate_validator()` takes a whole validator.
- The NoSecurity endpoint is offered only with `Server(allow_no_security=True)` or `NoSecurity` in
  `set_security_policy()`. `Basic128Rsa15` and `Basic256` need `allow_deprecated_policies=True` on both sides. A server
  without any endpoint refuses to start with `ConfigurationError`.
- Generated application certificates have `cA = FALSE` (self-signed ones keep keyCertSign); keys are written atomically
  with mode 0600. `setup_self_signed_certificate()` only replaces certificates it generated itself.
- New: `Server.load_certificate_chain()` to send an intermediate chain, `UaStatusCodeError(code, detail)`.

Users and permissions:
- The default user manager accepts Anonymous as read-only (read, browse, subscribe, history read; no write, call or
  node management) and rejects UserName and X509 tokens with `Bad_IdentityTokenRejected`. `admin` with any password
  is gone, and so is `Server.allow_remote_admin`. `PermissiveUserManager` remains as an explicit, insecure opt-in.
- Identity tokens are matched to the endpoint's UserTokenPolicy (PolicyId, token type, security policy); an Anonymous
  token with an empty or wrong PolicyId gives `Bad_IdentityTokenInvalid`. A wrong password gives
  `Bad_UserAccessDenied`. No UserName policy is advertised on an unsecured endpoint unless an encrypting policy exists
  or `allow_plaintext_password` is set.
- X509 user tokens are validated against a separate user trust list (`Server.set_user_trust_store()`); without one
  they are refused, except for the certificates registered with a `CertificateUserManager`. The user manager receives
  the leaf certificate only. A session whose X509 user certificate expires drops to Anonymous (or is closed when the
  endpoint offers no Anonymous policy).
- After 5 failed logins from one peer, further ActivateSession requests are delayed from 1 s up to 30 s.
- `SimpleRoleRuleset` takes a map from request type to role; `Permission` has an `Anonymous` level;
  `SessionManager.activate_session` is async.

Client:
- A client that took its security from GetEndpoints compares that list with CreateSession's ServerEndpoints and fails
  with `Bad_SecurityChecksFailed` when they differ. Endpoints are no longer re-fetched on reconnect.
- `HaSecurityConfig` needs a `server_certificate` or a `trust_store` when security is on.
- Publish requests are pipelined: up to `UaSession.max_outstanding_publish_requests` (default 10) are in flight,
  sized by the number of Subscriptions and the measured round trip, each with a timeout from the keep-alive time.
  Acknowledgements are kept until the response to the request that carried them arrives (`max_pending_acks`, 2000),
  and messages fetched with Republish are acknowledged too. Subscriptions register with `UaSession.register_sink`.
- A timed-out request is removed from the request table; a late response to it is dropped, a response for an id that
  was never sent closes the channel. A timed-out OpenSecureChannel no longer blocks every later renewal.
- `connect()` on a connected client raises; a failure during `connect()` closes the Session it created.
  `disconnect()` closes the local Subscriptions, and a later `connect()` doesn't bring them back. After a reconnect,
  Subscriptions are restored before publishing resumes; the stale watchdog keeps running.
- The client checks the server certificate's ApplicationUri against the endpoint's. `Client(url)` refuses schemes
  other than `opc.tcp`; a URL without a port uses 4840. A user token type the endpoint doesn't offer raises
  `ConfigurationError` before anything is sent.
- `Node.call_method` converts arguments to the method's declared InputArguments types; services take a per-call
  `timeout`. `UaClient.add_state_listener` is public. `get_keepalive_count` and `get_subscription_revised_params`
  are removed; use `subscription_parameters`.
- `HaClient` needs at least two server URLs.
- A session timeout revised by the server is logged at INFO, not WARNING: revising it is normal (OPC 10000-4, 5.7.2).

Client subscriptions (OPC 10000-4, 5.13 and 5.14):
- `subscription_parameters(period, ...)` derives the keep-alive count from a keep-alive time (default 10 s) and the
  lifetime count from a lifetime (default 300 s), never below three times the keep-alive; `MaxNotificationsPerPublish`
  is 0. A `Subscription` stores the revised values (`revised`) and corrects a revised keep-alive above 60 s once.
- The default sampling interval of `subscribe_data_change` is -1 (the publishing interval), not 50 ms.
  `unsubscribe` skips handles it doesn't know instead of raising; it keeps items the server couldn't delete and raises
  after removing the others. `modify_monitored_item` raises `ValueError` for an unknown handle and keeps the stored
  filter, queue size, discard policy and timestamps unless given.
- Notifications are delivered from a task per Subscription. A full inbox or event queue drops the oldest entry and
  counts it (`dropped_messages`, `dropped_events`); a slow handler delays only its own Subscription. Handlers may
  return any awaitable. Duplicate messages are dropped and missing ones are fetched with Republish
  (`max_republish`, `republish_missing`). `Bad_Timeout` marks the Subscription lost; `Good_SubscriptionTransferred`
  ends it without recreating. `Subscription.close()` ends it locally; `Subscription.state` is new.

File transfer (OPC 10000-5, Annex C):
- `UaFile.read()` reads in chunks until an empty ByteString and no longer uses `Size`; `write()` is chunked.
  `UaFile(node, mode, chunk_size=, timeout=)` validates the open mode, resolves Methods once with a fallback to the
  FileType Methods, refuses a second `open()` and sends no Close for a closed file. New: `read_chunk`, `iter_chunks`,
  `adopt`, `get_mime_type`, `FileTransferError`, `InvalidStateError`. `client/ua_file.py` is a deprecated wrapper,
  removed in 4.0.0.

Server file transfer (OPC 10000-20):
- New: `Server.add_file(parent, name, provider, writable=, max_size=, mime_type=, write_role=)` serves a path or a
  `FileProvider` (`PathFile`, `MemoryFile`) as a FileType Object, and `Server.add_directory(parent, name, root, ...)`
  serves a directory tree as a FileDirectoryType Object with CreateDirectory, CreateFile, Delete and MoveOrCopy.
  Handles belong to a Session and are released when it ends; one writer or many readers; bounded handles, read and
  write sizes and entries. Names, symbolic links and resolved paths are checked so nothing leaves the root.
  `Server.refresh_directory()` picks up changes made outside OPC UA.
- `ServerCapabilities/MaxByteStringLength` has a value (`InternalServer.max_byte_string_length`, default 1 MiB).
- `InternalSession.add_close_listener(callback)` calls `callback(session, reason)` when a Session ends.

Certificate management over OPC UA (OPC 10000-12, 7.10, push model):
- New: `Server.enable_push_management()` (needs `set_pki_directory`) serves the ServerConfiguration Object: TrustLists
  (a FileType of `TrustListDataType`, `OpenWithMasks`, `CloseAndUpdate`, `AddCertificate`, `RemoveCertificate`),
  `UpdateCertificate`, `CreateSigningRequest` (a new key waits in `own/pending/`), `GetRejectedList`,
  `GetCertificates`, `ApplyChanges` and `CancelChanges`. Changes are queued in one transaction and written to the PKI
  directory all or nothing at `ApplyChanges`; a new certificate is used by new channels, open channels close after the
  answer, and clients that are no longer trusted are disconnected. TrustListUpdated and CertificateUpdated audit events
  are raised.
- Breaking: only a user with `UserRole.SecurityAdmin` over a SignAndEncrypt channel may call them
  (`enable_push_management(min_security_mode=)` relaxes it to Sign). `CertificateUserManager.add_security_admin()`
  maps a certificate to that role. The optional ServerConfiguration nodes that are not supported (ConfigurationFile,
  KeyCredentialConfiguration, ResetToServerDefaults, ...) are removed from the address space.
- Breaking: a certificate is kept in `rejected/certs` only when it is valid but untrusted and its peer proved
  possession of the key (the validator no longer writes the folder; `CertificateValidator.keep_rejected()` does); one
  peer address keeps at most 10 files. A chain-incomplete or expired certificate is no longer kept.
- The own certificate of a PKI directory is the newest one that has a key in `own/private`, not the first key by name.
- `TrustStore` can read its lists back, replace or change them (`write_lists`, `write_certificate`,
  `remove_certificate_files`) with a `FileJournal` that undoes the writes, and counts its loads (`generation`).

High availability:
- `HaClient` keeps a Healthy active server whatever the others report, uses the best Degraded server when none is
  Healthy, never resets a connected standby for its ServiceLevel, and disconnects a server in maintenance
  (ServiceLevel 0). Probe and manager default to 5 s and wake each other. A server that reports no Warm or Hot
  `RedundancySupport` is not used unless `HaConfig(allow_unsupported_redundancy=True)`.
  `HaSecurityConfig` takes user credentials. Unknown subscription names raise `KeyError`; `HaClient.status()` is new.

Command line (`enginir-opcua`):
- One command with subcommands replaces the eleven `enginir-ua*` scripts, which are deprecated aliases until 4.0.0.
  `python -m enginir_opcua` works too, and the `tools/ua*` helper scripts of the repository are gone.
- `--password` is gone; use `--ask-password` or `ENGINIR_OPCUA_PASSWORD`. A password in the URL is warned about.
- Errors are one line on stderr with exit status 1, usage errors give 2, and Ctrl-C ends a command without a traceback.
  `--timeout` is a float of seconds and defaults to 4 (it was an integer defaulting to 1); `--verbose LEVEL` is
  `--log-level LEVEL`; the option `-i/--namespace` that did nothing is gone; `uals --depth` must be at least 1.
- `write` and `call`: every `--datatype` that was offered works (`guid`, `bytestring` as hex, `xmlelement`,
  `localizedtext`, `datetime` as ISO 8601, UTC without a zone), `write` reads the DataType of the node by default
  (`--datatype auto`), and a comma no longer makes an array: pass `--array` (and `--separator`). `call` takes one
  argument per `ARG` and refuses a node with several methods unless `-m` is given. The old `-l true|false|guess` forms
  work in the old scripts only.
- `server` is a demo: it prints a banner, listens on 127.0.0.1 by default (it was 0.0.0.0; the Docker image passes
  `--url opc.tcp://0.0.0.0:4840`), and `--shell` keeps the server running while the shell is open. `shell` opens a
  Python shell with `client`, `root`, `objects` and `mynode`. `--pki-dir` and `--security Policy,Mode` set up
  secure connections; control characters in text from a server are printed escaped.

Synchronous interface (`enginir_opcua.sync`):
- Subscription handlers, state listeners and `connection_lost_callback` run on a handler thread, not on the loop, so
  they may call the sync API; a sync call on the loop thread raises `RuntimeError` instead of deadlocking. The handler
  queue is bounded (`handler_queue_maxsize`, 1000): the oldest call is dropped and `Observer.on_messages_dropped` is
  called.
- A call that times out is cancelled before `TimeoutError` is raised. `Subscription.next_event(timeout)` and iteration
  are no longer cut by the wrapper timeout.
- `ThreadLoop` is a daemon thread that can be started again after `stop()`, so `connect()` after `disconnect()` works
  and nodes obtained before stay valid; still-connected clients are disconnected at exit. `ThreadLoop` is no longer a
  `threading.Thread` subclass and `ThreadLoopNotRunning` is a `RuntimeError`.
- The sync `Client` takes `auto_reconnect`, `reconnect_max_delay`, `reconnect_request_timeout`, `observer` and
  `handler_queue_maxsize`, has `state` and `add_state_listener`, and no longer takes the unused `user_manager`. The
  sync `Server.register_namespace` and `get_namespace_index` call their parameter `uri`. The signatures, the missing
  methods and the docstrings of the sync classes follow the async ones; tuples and dicts come back as such.
- `disconnect()` and `stop()` can be called twice.

Observer:
- `Client(observer=...)` and `client.observer` set an `Observer`. The module and its hooks are documented
  (`on_messages_dropped` and `on_messages_lost` are new since 2.x). `on_messages_dropped` also reports events dropped
  from the iterator queue of a Subscription and events for a handler that lacks the method.

Documentation:
- Spec references in docstrings are citations such as `OPC 10000-4 v1.05, 5.9.2`, not links. The section numbers were
  renumbered where the 1.04 numbers were used (Part 4 inserted 5.4, so the service sets moved by one). The client and
  server overviews and the sync, Observer and command-line pages are written.

Status codes:
- Status codes are matched by their top 16 bits, so `except ua.uaerrors.BadNodeIdUnknown` also catches a code with info
  bits set. `error.code` is the full code as received; `StatusCode.name` and `.doc` ignore the info bits.
- `StatusCode("unknown name")` raises `UaError` instead of `AttributeError`.

NodeId, QualifiedName and LocalizedText strings (OPC 10000-6, 5.1.12):
- `NodeId.to_string()` writes `[svr=<index>;][ns=<index>;|nsu=<uri>;]<identifier>`. The server index comes first and
  is spelled `svr=`, not `srv=` after the identifier. Namespace URIs are percent-encoded.
- `NodeId.from_string()` is strict: unknown keys, trailing components, malformed numbers and GUIDs, invalid Base64 and
  `svu=` raise `UaStringParsingError`. `srv=` is still read, but only in front. `b=` is Base64 only; the `0x` hex form
  and the raw-bytes fallback are gone. Spaces after `;` are no longer allowed. `nsu=` strings give `ServerIndex` 0.
- `QualifiedName.to_string()` writes names in namespace 0 without a prefix (`Root`, not `0:Root`), which also changes
  `Node.get_path(as_string=True)`. `QualifiedName.from_string()` takes `namespaces=` for the `nsu=` form, and `a:b` is
  a name. Swapped or wrongly typed constructor arguments raise `TypeError`.
- `LocalizedText.to_string()` writes `LocalizedText(Locale=<repr>, Text=<repr>)`, which `from_string()` reads back
  exactly. A text of `"None"` stays a text.

Identity and ordering:
- `ExpandedNodeId` equality and hashing include `NamespaceUri` and `ServerIndex`. A `NodeId` equals an `ExpandedNodeId`
  only when the latter has no URI and ServerIndex 0.
- A text identifier with type ByteString, or bytes with TwoByte or FourByte, raises `UaError`. Comparing a NodeId with
  something else raises `TypeError`.
- An `ExpandedNodeId` with a NamespaceUri is encoded with namespace index 0.

Variant and defaults:
- `Variant` equality compares `Dimensions` and `is_array`. A Variant copied from a Variant keeps both.
- A Variant can't hold a DiagnosticInfo; constructing or decoding one raises `UaError`.
- Type guessing raises `UaError` for objects it doesn't know instead of assuming ExtensionObject. `VariantTypeCustom`
  accepts 26 to 63 only.
- A scalar `None` is accepted for every nullable type and becomes that type's null value.
- ArrayDimensions are written only for two or more dimensions, all above 0, so an empty multi-dimensional array comes
  back flat.
- `get_default_value()` returns the null values: DateTime 1601-01-01 UTC and the all-zero Guid instead of the current
  time and a random Guid.
- Boolean fields of generated structures default to `False` instead of `True` (OPC 10000-6, 5.1.2), so
  `ua.ReadRawModifiedDetails()` no longer asks for modified values and bounds, and `ua.MonitoringParameters()` no
  longer discards the oldest value. Code that built these structures without setting the field must set it.
- `WriteMask` has the members for bits 22 to 25.

XML import and export:
- Exporting a variable whose XmlElement value is null no longer raises AttributeError.
- `XMLParser.parse` and `XmlImporter.import_xml` with an empty `xmlstring` report the XML parse error instead of
  looking for a file; `get_used_namespaces` and `get_used_servers` return an empty string for an empty entry.
- `xmlexporter.indent` uses `xml.etree.ElementTree.indent`, which removes a DeprecationWarning;
  `XmlExporter.extobj_ordered_elements`, which nothing read, is removed.

Encoding and decoding:
- A decoded ExpandedNodeId with a NamespaceUri and no ServerIndex has ServerIndex 0, not None, so it equals the
  ExpandedNodeId that was encoded.
- A structure field that is None, such as the TargetName that RelativePath.from_string leaves empty, is encoded as
  the structure's null value instead of raising TypeError.
- Decoding malformed input raises only `UaError` subclasses: unknown enum values, bad NodeId formats, union switches
  out of range, unassigned optional-field bits, ExtensionObject length -1 for an unknown type, inconsistent Variant
  dimensions, nesting deeper than 100 levels and impossible array counts.
- Arrays accept any iterable and raise `UaError` for a scalar or a `str`; a non-list used to be sent as a null array.
- An ExtensionObject with an XML body decodes to an `ExtensionObject` with `Encoding == 2` and the XML in `Body`.
- LocalizedText leaves out empty Locale and Text on the wire.
- `DiagnosticInfo.NamespaceURI` is `NamespaceUri`, `InnerDiagnosticInfo` is a `DiagnosticInfo`, and nesting deeper
  than 10 levels raises.
- `Buffer.copy(n)` beyond the remaining bytes raises, `Buffer.rewind()` stays inside its window, and
  `Buffer(data, start, size)` checks the window.
- `ua_binary.test_bit` is `is_bit_set` and returns a `bool`.

Messages and paths:
- `ua.DataChangeFilter().Trigger` defaults to `StatusValue`.
- The `*Attributes` classes keep a `SpecifiedAttributes` value passed by the caller (except `DataTypeAttributes`).
- `Message.SequenceHeader()` and `SecurityHeader()` are `sequence_header()` and `security_header()`.
  `Header.header_size` is a read-only property, `body_size` and `packet_size` are constructor fields, and
  `MessageType.Invalid` and `ChunkType.Invalid` are gone.
- `RelativePathElement()` defaults to `IsInverse=False` (forward).
- RelativePath text errors raise `UaStringParsingError` instead of `ValueError`. Only standard ReferenceTypes in
  namespace 0 are accepted by name, so `<Server>` and `<2:HasComponent>` raise. A forward or inverse step without a
  reference name raises when written.

Transport (OPC 10000-6, 7.1):
- `TransportLimits` keeps the peer's limits apart (`send_max_message_size`, `send_max_chunk_count`).
  `max_message_size` and `max_chunk_count` are this side's receive limits, and a configured 0 means the default
  (100 MiB, 1601 chunks), not unlimited. The same holds for `Client.max_messagesize` and `max_chunkcount`.
- The client's Hello carries its real limits; the `ua.Hello` defaults are 65535, 65535, 100 MiB and 1601.
- A Hello or Acknowledge with buffers below 8192 bytes is rejected with `Bad_InvalidArgument`, so a server
  configured below 8192 can't be reached. An EndpointUrl above 4096 bytes gets `Bad_TcpEndpointUrlInvalid`.
- A connection without a Hello is closed after `InternalServer.hello_timeout_seconds` (30 s). At the connection limit
  the server closes its oldest connection without a session instead of refusing the new one.
- A request above the server's limits fails locally with `Bad_RequestTooLarge`; a response above the client's limits
  becomes a ServiceFault `Bad_ResponseTooLarge`. An Abort chunk fails its request at once.
- New server limits `max_string_length` and `max_byte_string_length` (16 MiB each, in bytes) and `max_array_length`
  (1,000,000 elements), in `ServerLimits`, as `Server` attributes and published as `MaxStringLength`,
  `MaxByteStringLength` and `MaxArrayLength` in ServerCapabilities (OPC 10000-5, 6.3.2). A request with a longer
  String or ByteString, or a longer array in a Variant, gets a ServiceFault `Bad_EncodingLimitsExceeded` (OPC
  10000-4, 5.3). A Write value over a limit gets `Bad_OutOfRange` for that operation (5.11.4.4), and a Call input
  argument over a limit gets `Bad_OutOfRange` in `InputArgumentResults` with `Bad_InvalidArgument` for the Method
  (5.12.2.4). The default `max_byte_string_length` rose from 1 MiB to 16 MiB, which also raises the default chunk size
  of the file service. The client side is unchanged.
- Channel failures send an Error message and close the connection, so clients see `Bad_SecurityChecksFailed`,
  `Bad_TcpSecureChannelUnknown` or `Bad_SecureChannelTokenUnknown` instead of a timeout.
- Hello is handled by `OPCUAProtocol` (`UaProcessor.accept_hello`). Removed: `UASocketProtocol.receive_buffer`,
  `is_receiving` and `_process_received_data`.

SecureChannel (OPC 10000-6, 6.7; OPC 10000-4, 5.6.2):
- `SecureConnection` is `SecureChannel`, with no alias. Removed: `next_security_token`, `prev_security_token`,
  `revolve_tokens`, `UaClient.revolve_security_token` and the previous-key members of the crypto classes. New:
  `SecurityPolicy.make_symmetric_cryptography()`.
- The server clamps RevisedLifetime to `InternalServer.channel_settings` (10 s to 1 h; a request for 0 gets 1 h).
  TokenIds are random. Keys are chosen by TokenId, every token is accepted until 125 % of its lifetime, and a channel
  without a valid token is closed.
- Issue on an open channel and Renew on an unopened one fail with `Bad_RequestTypeInvalid`. Nonces, the receiver
  thumbprint, certificate, policy, mode and protocol version are checked on both sides.
- The client renews after 75 % of each revised lifetime, at least every second.
- A chunk with an out-of-order sequence number raises `TransportError` with `Bad_SecurityChecksFailed`, like a wrong
  RequestId, so a client fails its pending requests with that status. A `HEL` from a server raises `TransportError`
  with `Bad_TcpMessageTypeInvalid`. `SecureChannel.receive_from_header_and_body` is typed `ReceivedMessage` and no
  longer decodes a Hello. `local_nonce` and `remote_nonce` start as `b""` instead of `0`.

Server sessions (OPC 10000-4, 5.7):
- `Session` and `SessionManager` (`iserver.session_manager`) replace the session state of `InternalSession`. A channel
  can carry several sessions; every request is matched to its session by AuthenticationToken and has to arrive on
  that session's channel. Removed: `InternalServer.create_session`, `lookup_external_session`,
  `register_external_session`, `unregister_external_session` and `InternalSession.max_connections`;
  `InternalSession.transfer_subscriptions(params)` takes no callback.
- At most `session_manager.max_sessions` (100) sessions; at the limit the oldest session that was never activated is
  closed, otherwise CreateSession gets `Bad_TooManySessions` (was `Bad_MaxConnectionsReached`). A ClientNonce shorter
  than 32 bytes is rejected.
- Requests on an unknown, closed or timed-out session get `Bad_SessionIdInvalid`, on a created but not activated one
  `Bad_SessionNotActivated`. CloseSession of an unknown session is no longer Good.
- A session the server ends (timeout, lost channel) keeps its subscriptions until their own lifetime ends, so a client
  can transfer them; only CloseSession with deleteSubscriptions deletes them. An activated session survives the loss
  of its channel until its timeout.
- Empty operation arrays return `Bad_NothingToDo`, arrays above `iserver.operation_limits` `Bad_TooManyOperations`;
  an undecodable request body `Bad_DecodingError`. Requests of a session may run concurrently.
- `CloseSecureChannelRequest` is honoured only as a CLO message.
- `Server.default_timeout` is removed. `start()` after `stop()` gives the same endpoints as the first start;
  `stop()` sets ServerState to Shutdown, withdraws discovery registrations and closes sessions and subscriptions.
  `register_to_discovery()` refuses a period above 600 s; `unregister_from_discovery()` of an unknown URL raises
  `UaError`.

Subscriptions (OPC 10000-4, 5.13 and 5.14):
- The publishing interval is revised to between 50 ms and 1 h (0 or less gets 50 ms), also for in-process
  subscriptions; keep-alive 0 becomes 1; the lifetime count is at least 3 × keep-alive and interval × lifetime is at
  most 24 h. ModifySubscription applies and returns the revised values. The first message goes out after the first
  cycle.
- Subscriptions follow the Part 4 state machine; an expired subscription sends `Bad_Timeout` and the owner's queued
  Publish requests are answered. Sequence numbers roll over to 1; MaxNotificationsPerPublish and MoreNotifications
  are honoured; Priority decides between waiting subscriptions.
- Republish keeps the message; an unknown sequence number gives `Bad_MessageNotAvailable`. Acknowledging an unknown
  sequence number gives `Bad_SequenceNumberUnknown` for that entry. The retransmission queue holds 2 × the Publish
  limit per session.
- At most 10 Publish requests per session (`max_publish_requests_per_session`); one more answers the oldest with
  `Bad_TooManyPublishRequests`. At most 100 subscriptions per session (`max_subscriptions_per_session`).
- TransferSubscriptions requires the same user (anonymous only with the same client certificate), moves the queue
  and both Publish bindings, tells the previous owner `Good_SubscriptionTransferred` and honours SendInitialValues.
- `InternalSubscription.publish()`, `has_published_results()` and `_trigger_publish` are removed.

Attribute, method and view services (OPC 10000-4, 5.8 to 5.12):
- No role bypasses AccessLevel or WriteMask, Admin included; only the server's own in-process session is exempt. Remote
  clients can't write read-only variables or attributes without the WriteMask bit, `NamespaceArray` included.
- Write checks the DataType (subtypes allowed), ValueRank, ArrayDimensions and null values; a StatusCode or
  SourceTimestamp from a client needs the StatusWrite or TimestampWrite bit, otherwise `Bad_WriteNotSupported`.
  `Node.write_value` no longer sends a SourceTimestamp. A value setter's return value is the write result, and
  `Server.write_attribute_value` raises on a bad result. A client write to an attribute with a value callback is
  `Bad_NotWritable`.
- Read honours IndexRange and TimestampsToReturn and ignores DataEncoding; a variable that was never set reads as
  `Bad_NoValue`. `ua.IndexRange` implements NumericRange (OPC 10000-4, 7.27) for Read, Write, HistoryRead, monitored
  items and PubSub targets.
- Call checks that the method belongs to the object, Executable/UserExecutable and every input argument.
  `Node.call_method` sends Python ints as Int64, so methods with other integer argument types need typed Variants.
  Hand-built `ua.Argument` objects need a ValueRank; a method without a callback gives `Bad_NotSupported`.
- Browse honours ResultMask, NodeClassMask and RequestedMaxReferencesPerNode; BrowseNext and continuation points
  exist; unknown nodes give `Bad_NodeIdUnknown`. With ResultMask 0, `get_children` returns empty fields.
- AddNodes from a client: namespace 0 is refused (`Bad_NodeIdRejected`, also `instantiate()` with `idx=0`), the
  parent reference must be hierarchical and the BrowseName unique. AddReferences refuses duplicates; DeleteNodes and
  DeleteReferences refuse namespace 0.

Monitored items and events (OPC 10000-4, 5.13):
- QueueSize 0 or 1 means 1 for data items (it used to mean 10 000); the maximum is 1000. The sampling interval is
  revised (0 becomes 10 ms, a negative value the publishing interval). A null filter in ModifyMonitoredItems removes
  the filter. A deleted monitored node delivers `Bad_NodeIdUnknown`. `InternalSubscription(max_queue_size=...)` is
  now `limits=MonitoredItemLimits(...)`; `MonitoredItemValues` is removed.
- Events also reach the Server object and every notifier above their source. `EventGenerator` no longer clears other
  EventNotifier bits; the default Message is a LocalizedText; DaylightSavingInOffset is set only while DST applies.
  68 fields of the generated event classes now declare built-in types.

Alarms and Conditions (OPC 10000-9):
- New server API: `await server.create_condition(source, condition_type, name, **options)` creates a Condition or
  Alarm Object (ConditionId = its NodeId, referenced with HasCondition) and returns a handle with `activate()`,
  `deactivate()`, `update_value()` (level, deviation and off-normal alarms, with deadbands), `acknowledge()`,
  `confirm()`, `add_comment()`, `enable()`, `disable()`, `shelve_timed()`, `shelve_one_shot()`, `unshelve()` and
  more. Every change raises one Event with all fields and sets Retain as Part 9 says. Branches (previous states) are
  opt-in with `branches=True`. Also `server.delete_condition()`, `server.get_condition()`, `server.conditions` and
  `server.refresh_required()`. Rate-of-change alarms can be created but have no value logic.
- The Methods Enable, Disable, AddComment, Acknowledge, Confirm, TimedShelve, OneShotShelve, Unshelve (and the
  `2` variants with a Comment), ConditionRefresh and ConditionRefresh2 work, with the Part 9 result codes. They can be
  called on the ConditionId with the well-known MethodId. `bind_condition_methods` is removed: ConditionRefresh is
  always available (it used to answer `Bad_NotExecutable` even when bound). RefreshStart, RefreshEnd and
  RefreshRequired ignore the content filter and reach every Event item of the Subscription; refreshing another
  session's Subscription gives `Bad_UserAccessDenied`; retained Conditions and branches are replayed with their EventId.
  An Event queue overflow that loses Condition Events is followed by a RefreshRequiredEvent.
- New client helpers in `enginir_opcua.common.conditions`: `acknowledge`, `confirm`, `add_comment`, `enable`,
  `disable`, shelving calls, `condition_refresh`, `condition_refresh2` (falls back to ConditionRefresh),
  `condition_event_filter` and `ConditionTracker` (the current-alarm algorithm of Part 9, 4.5).
  `Subscription.subscribe_alarms_and_conditions()` now calls ConditionRefresh after subscribing; pass
  `refresh=False` for the old behaviour.
- Method nodes of the standard address space, of imported NodeSets without an `Executable` attribute and of
  instantiated types are executable (the NodeSet default is true); they used to be refused with `Bad_NotExecutable`.
  Method callbacks can read the calling session in `enginir_opcua.server.internal_session.current_call_session`.
  `instantiate(..., optional=[names])` creates the named Optional children even with `instantiate_optional=False`.
- Condition Events always have the ConditionId (`NodeId`) field; EventIds are 16 random bytes.

History (OPC 10000-11):
- `HistoryStorageInterface` is replaced for custom backends: reads take a `TimeDomain` and return a `Page`; saves are
  `save_node_value()` and `save_event()`; new `has_node()`, `has_event()`, `flush()` and `stores_server_timestamp`.
- SQLite history files from earlier releases are refused with an error naming the file.
- A HistoryRead of a node that isn't historized gives `Bad_HistoryOperationUnsupported`, without the HistoryRead bit
  `Bad_NotReadable`. Two of start, end and count are required. Equal timestamps return the latest value with the
  ExtraData bit; empty ranges give `Good_NoData`.
- `Node.read_raw_history()` and `read_event_history()` without arguments read everything until now, and with only a
  count the newest values; `read_raw_history` defaults `return_bounds` to False.
- `validate_table_name` and `SqlInjectionError` are removed. `set_storage()` after historizing raises. A notifier's
  event history includes the events of the sources below it.

Crypto:
- A security policy whose keys are not derived yet raises UaError naming the missing key instead of AttributeError,
  and an RSA policy refuses a certificate or key that is not RSA, or a missing one, with UaError.
- `SECURITY_POLICY_TYPE_MAP` values are tuples. `encrypt_asymmetric` and `sign_asymmetric` of the policy classes are
  class methods built from `encrypt_function` and `asymmetric_signer`. `Verifier.reset`, `Decryptor.reset` and
  `validator.check_uri` are removed.
- `setup_self_signed_certificate` raises ConfigurationError when the key file holds a key that is not RSA.
- The server writes the certificate of a refused peer to `rejected/certs` before it sends the error, so `GetRejectedList`
  right after a failed connect lists it. `CertificateValidator.keep_rejected()` lost its `background` argument and
  writes synchronously; a vanished rejected folder is logged at debug level only.
- Without a revocation list, a validator warns once, when it first accepts a CA-issued certificate unchecked, and
  names the issuer; it no longer warns at every start, and never for self-signed certificates.
- Verifiers raise `ua.uaerrors.SignatureError` and decryption failures `ua.uaerrors.DecryptionError` (both
  `UaError`); `uacrypto.InvalidSignature` is gone.
- A bad ActivateSession client signature is answered with `Bad_ApplicationSignatureInvalid`, a bad or missing X509
  user-token signature with `Bad_UserSignatureInvalid`.
- `sign_asymmetric` raises without a signing policy instead of returning the data, so an X509 user token on an
  endpoint without security fails on the client.
- `check_certificate()` returns a list of problems (empty when fine) instead of `True` for "has problems".
  `x509_from_der()` raises `UaError` on malformed input; `split_certificate_chain()` returns the whole chain.
- `SecurityPolicyType` lives in `crypto/security_policy_type.py` (still `ua.SecurityPolicyType`).
  `revolved_expired_key` was renamed and then removed with the previous-key handling.
- AES-256 policies pad to 16-byte blocks (wire-compatible).

XML import:
- Nodes marked `DesignToolOnly`, their children and references to them are skipped (OPC 10000-6, F.7).
- `import_xml` raises `NodeSetError` (a `UaError` and a `ValueError`) when a node is refused or cannot be placed: every
  node needs a hierarchical parent (OPC 10000-4, 5.8.2), taken from `ParentNodeId`, a hierarchical reference or, for a
  DataTypeEncoding, `HasEncoding`. Nothing is exempt from the status check. The returned list holds only nodes that
  exist; `XmlImporter.failures` lists the rest in non-strict mode. A DataTypeEncoding that no DataType refers to is
  skipped with a warning.
- Required models are compared by `ModelVersion`, then `PublicationDate`, and all missing ones are named.
  NamespaceMetadata objects created by an import have `IsNamespaceSubset = False`.
- XML values follow XML Schema: booleans are `true`, `false`, `1` or `0` (anything else raises), a dateTime without a
  zone is UTC, an empty `<String/>` is `""`. Minified files, `ServerUris`, Views and Matrix values import. NodeId,
  ExpandedNodeId and QualifiedName values use the server's namespace indices.
- Executable, AccessLevel 0, Historizing and WriteMask of imported nodes are kept; the User* variants are read but only
  exported when they differ from the primary attribute. Option sets, subtyped structures, inherited fields and the
  Default Binary encoding id are imported; DataTypeDefinitions are written with the Write service.
- Export writes only attributes of the UANodeSet schema, keeps Symmetric, IsAbstract, AccessLevel 0, WriteMask, Views,
  `IsOptionSet` and `AllowSubTypes`, maps namespace indices in values, no longer lists the base URI first, and
  `export_xml_by_ns` writes a `Models` element. `build_etree_chunked` no longer reconnects.

Custom types:
- Every `Client` and `Server` has its own type registry, `client.types` / `server.types`, keyed by namespace URI and
  identifier. Classes made by `load_data_type_definitions()` or `import_xml()` belong to that session: a client in the
  same process as a server must load the definitions itself, and sending a class of another session raises. The
  module-level `ua.extension_objects_by_*`, `ua.enums_*`, `ua.get_type` and `ua.register_*` only serve namespace 0 and
  legacy registrations; `ua.<Name>` still binds the first class of a name.
- `Buffer` carries the registry of the connection (`Buffer.types`) that decodes ExtensionObjects.
- `new_struct_field(array=True)` has `ArrayDimensions = [0]`; `new_enum` keeps the `Value` of an `EnumField`;
  enumeration members whose names clean to the same identifier raise; `Server.load_data_type_definitions()` takes
  `overwrite_existing`, which now reloads changed definitions; generated defaults no longer use random or current values.
- Structure fields with ValueRank 2 or more are nested lists, encoded as inline matrices (OPC 10000-6, 5.2.5), and
  `UnionWithSubtypedValues` definitions are built. Option sets are found below Byte, UInt16, UInt32 and UInt64 and use
  the width of their base type instead of always 32 bits. An enumeration without DataTypeDefinition is built from its
  `EnumValues` or `EnumStrings` Property.
- The legacy loader for DataTypeDictionaries (`Client.load_type_definitions()`) finds arrays by the `LengthField`
  attribute of the dictionary, not by field names starting with `NoOf`, `__...Length` or `#`, and a generated file
  registers only structures that have a type id.
- The legacy loaders (`load_type_definitions()`, `load_enums()`) register their classes in the type registry of the
  client or server, not in the process-wide registry, and `StructGenerator.get_python_classes()` without an
  environment returns a new dictionary instead of writing into `ua`.
- `ua.DataTypeAttributes` has no `DataTypeDefinition` field and no reserved bit 22 (OPC 10000-4, 7.24.8).
- `StructNode.add_field(field_name, field_type, is_array)`; the dictionary builder checks every result.

Code generation:
- The generated code comes from the `nodeset` submodule, pinned to UA-Nodeset `UA-1.05.07-2026-05-01`.
  `schemas/regenerate.py` replaces `schemas/update_ua_nodeset.py`.

Node helpers:
- `CallbackService` keeps every listener, ordered by priority and then insertion order (a second listener with the
  same priority used to replace the first); any awaitable result is awaited and dispatch works on a snapshot.
- `string_to_val` is the inverse of `val_to_string`: lists quote elements that contain commas, quotes or brackets,
  nested and empty lists work, enumerations read by name. Invalid text raises `ValueError`, integers are range
  checked, Booleans are `true`/`false`/`1`/`0` in any case (the legacy `on`/`yes` are gone), and types without a text
  form raise `NotImplementedError`.
- `get_references`, `get_children` and the other browse helpers raise on a Bad browse result and release the
  continuation point when a page fails. `get_child` and `get_children_by_path` accept a target only when the whole
  path resolved. `read_event_history` and `read_raw_history` read every page and release an open continuation point;
  `history_read_events` takes a continuation point. `history_update` checks the operation results.
- `write_array_dimensions` writes a `UInt32[]`; `read_value_rank` returns a plain integer above four dimensions.
  `Node.add_reference` sends the target NodeClass.
- A failed method call raises `UaStatusCodeError` with `input_argument_results` and `input_argument_diagnostic_infos`;
  multi-dimensional arguments are converted.
- `create_method` takes `(nodeid, bname, callback, inputs, outputs)`; binding a callback on a client session raises
  `UaError` (pass no callback to create the Method node without one). Arguments are named `Input<i>`/`Output<i>`,
  an argument type given as a list is an array. A symmetric ReferenceType has no InverseName, a non-symmetric one
  needs it (`ValueError`). `add_object_type`, `add_variable_type` and `add_data_type` take `is_abstract`.
- New variables: a list has ValueRank 1 (or the number of dimensions) and ArrayDimensions of zeros (unknown maximum),
  there is no Description, and a VariableType without a value is scalar; falsy initial values are kept. Encoding
  objects have the DataTypeEncodingType type definition. `create_data_type` adds no second HasSubtype reference.
- Recursive `delete_nodes` and `copy_node` follow only aggregating references (HasComponent, HasProperty, ...), each
  node once, children first; nodes another parent still aggregates are kept. `copy_node` copies EventNotifier,
  IsAbstract and the ModellingRule, takes `referenceType` (default: the reference the source hangs on), and removes
  what it created when it fails.
- `instantiate` accepts only ObjectTypes and VariableTypes, skips placeholder and ExposesItsArray declarations,
  instantiates the declarations of a child's own type (and its EventNotifier), checks every AddNodes result and removes
  what it created when it fails.
- Event filters: `where_clause_from_evtype` uses the `OfType` operator (one element per type, combined with `Or`)
  instead of listing the subtypes; an EventType without a supertype chain to BaseEventType raises `UaError`.
- State machines: `FiniteStateMachine.install()` creates a concrete subtype (or takes `state_machine_type`).
  `add_transition(..., from_state=, to_state=)` creates the FromState and ToState references; names and numbers
  must be unique, number 0 is valid, there is at most one initial State, and `change_state` rejects a transition that
  does not connect the current state to the new one and always raises a TransitionEvent (default message
  "<from> to <to>"). `State`/`Transition` ids follow the DataType of the `Id` property. The classes
  `ExclusiveLimitStateMachine`, `FileTransferStateMachine`, `ProgramStateMachine` and `ShelvedStateMachine` are removed.
- `get_node_supertypes` returns the nearest supertype first; `get_nodes_of_namespace` can return namespace 0 and raises
  `UaError` for an unknown URI; `get_node_children` and `get_node_subtypes` list each node once.

PubSub (OPC 10000-14, experimental; see `docs/usage/pubsub/overview.rst`):
- A PublisherId is encoded with the type of its Variant (UInt64 uses type bits 011), so ids that were read from a file
  or built as `Variant(5, VariantType.UInt16)` keep their type. `UadpHeader` refuses a PublisherId that is a plain `int`:
  wrap it in `Byte`, `UInt16`, `UInt32`, `UInt64` or `String`. `OpcUdp.get_publisher_id()` returns a typed value.
- UADP messages: the Valid flag, the PromotedFields size (bytes), Event DataSetMessages, header-only heartbeat key
  frames, DataSetMessage sizes (padding no longer shifts the next message), the chunk layout and the discovery headers
  follow Part 14. A receiver skips messages with an unknown version or reserved values (`UadpSkip`, counted by reason);
  `UadpNetworkMessage.from_binary` raises `UadpSkip` for them, `decode_network_message` returns it. The classes
  `UadpDiscoveryRequest`, `UadpDiscoveryResponse`, `UadpDataSetDeltaRaw` and the three `Uadp*Resp` classes are gone;
  `UadpDiscoveryProbe` and `UadpDiscoveryAnnouncement` keep the headers and the body as bytes.
- RawData fields are padded to `MaxStringLength` and `ArrayDimensions`; fields that can't be sent as RawData make the
  DataSetMessage invalid (logged once). `PubSubDataSource.get_raw(fields)` takes the field metadata and no longer drops
  fields without a value.
- Sequence numbers start at 0 and roll over from 65535 to 0 (they used to skip 0 and 65535).
- `MessageReceiveTimeout` is in milliseconds and restarts with every message; a reader is `PreOperational` until its
  first key frame. DataSetMessages with a different major configuration version, a wrong number of fields, an
  out-of-range delta index, a duplicate or older sequence number, or `Valid = false` are dropped and counted.
  A null reader PublisherId matches every publisher. `ReaderGroup.set_name(name)` sets the name and
  `ReaderGroup(cfg)` keeps `cfg`.
- `Enabled` is honoured at every level, groups start in order of their `Priority`, publishing runs on a fixed
  schedule, an interval of 0 or less is refused, `KeepAliveTime` and `MaxNetworkMessageSize` are applied (a message
  above it isn't sent; a warning is logged once). `WriterGroup.new_uadp(priority=, address=)` sets the Priority and the
  unicast destination.
- UDP: loopback is applied for both values, a multicast subscriber joins the group on its `NetworkInterface` (an IP
  address or an interface name) and binds to the group address, IPv6 URLs keep their brackets. A unicast subscriber binds
  to its interface, to the URL's IP address or to loopback; it listens on all interfaces only with an explicit `0.0.0.0` or
  `::`. A connection without readers opens no receive address. Datagrams are queued (256) and handled by one task;
  malformed datagrams give a rate-limited warning on the module logger.
- `PubSub.start()` raises the first startup error and leaves nothing running; `stop()` is repeatable and never raises
  a cancellation; connections and datasets appear once in the address space, whatever their number; the remove methods
  await the deletion of the right node, stop what runs and update the configuration; `load_binary_file` raises
  `UaStatusCodeError(Bad_InvalidArgument)` for other files and `save_binary_file` writes a file it can load again.
- `SubScribedTargetVariables` writes only to variables whose AccessLevel allows it (the write is counted and logged
  once), applies `OverrideValueHandling` as in Part 14 Table 80 (also when the reader leaves Operational) and
  counts fields without a target. Readers built from a configuration get their sinks from the server. The
  AddReaderGroup, AddWriterGroup and RemoveGroup methods answer `Bad_NotImplemented`.
- A Bad field is sent as a Variant holding its StatusCode, an Uncertain one as a Variant holding its DataValue.
  `DataSetMeta.add_array` creates an array field, `remove_field` removes it, versions follow the changes, and
  `PublishedDataItems.Create` no longer inverts the promoted flag. `DataSetField.get_datatype_name(types)` looks the type up
  in the given registry.

Server infrastructure (workstream J):
- Reverse connect (OPC 10000-6, 7.1.2.6 and 7.1.3). `Server.add_reverse_connect(client_url, endpoint_url=None,
  retry_interval=5.0)` connects out to a listening client, sends a ReverseHello, keeps one such socket open per client
  and reconnects with a back-off; `remove_reverse_connect()` ends it. `Client.listen_reverse(listen_url, server_uri,
  endpoint_url=None)` waits for that server, also when the connection is lost and the session is reactivated;
  `ReverseConnectListener` shares one listening port between several clients (`Client.use_reverse_listener`). A
  ReverseHello of an unknown server is refused with `Bad_TcpEndpointUrlInvalid`. `ua.ReverseHello` and
  `ua.MessageType.ReverseHello` are new.
- Diagnostics (OPC 10000-5, 6.3.3). `Server.diagnostics` keeps the counters of `ServerDiagnosticsSummary`, which the
  standard nodes now return instead of a null value; `EnabledFlag` (default FALSE, writable by Admin and
  SecurityAdmin, or `server.diagnostics.enabled`) adds `SessionDiagnosticsArray`, `SubscriptionDiagnosticsArray`,
  `SessionSecurityDiagnosticsArray` and an Object per Session. The security diagnostics are returned only to a
  SecurityAdmin on a SignAndEncrypt channel, and to a Session about itself. `SamplingIntervalDiagnosticsArray` is no
  longer in the address space.
- Model change events (OPC 10000-3, 9.32). A request that adds or deletes nodes or references raises one
  `GeneralModelChangeEvent` from the Server Object; `async with server.model_change():` batches several calls into
  one event. A node that has a `NodeVersion` property gets a new value. `Server.model_change_events` is `"all"` (every
  changed node, the default) or `"versioned"` (only nodes with a `NodeVersion`).
- `enginir_opcua.common.programs.ProgramStateMachine` makes a Program of ProgramStateMachineType (OPC 10000-10) with the
  control Methods you supply, `Executable` that follows the state, `ProgramTransitionEvent`s, `ProgramDiagnostic`,
  recycle and instance counts, and deletion rules. Breaking: `ProgramStateMachine` of `common/statemachine.py` was a stub
  that raised `NotImplementedError` and is removed there.
- A structure field named `Encoding` (`SessionSecurityDiagnosticsDataType`) is encoded as a field and no longer as the
  encoding byte.

Quick setup (workstream K):
- `Server.quickstart(endpoint, profile="secure", pki="./pki", users=None, **overrides)` and
  `Client.quickstart(url, profile="secure", pki="./pki", username=None, password=None, **overrides)` return a
  configured object that is not started. The profile `secure` offers Basic256Sha256, Aes128Sha256RsaOaep and
  Aes256Sha256RsaPss with SignAndEncrypt on any network; `development` listens on loopback only, may also offer no
  security and warns at start. The PKI directory is created with a self-signed certificate at `Server.init()` and at
  the first `Client.connect()`; nothing is trusted automatically. The sync classes have the same methods.
- `enginir_opcua.config.ServerConfig`, `ClientConfig` and `ServerLimits`: `validate()` checks the whole configuration
  and raises one `ConfigurationError` that names every wrong setting (`server.pki: ...`); `from_toml(path)` reads a
  `[server]` or `[client]` table (unknown keys are errors, relative paths follow the file, no password is ever read
  from or written to the file) and `dump(path)` writes a commented file. `Server(config=...)` and `Client(config=...)`
  apply a configuration; the setters stay the low-level API. `Client(url)` now accepts `url=None` when a config is
  given.
- `FileUserManager` reads a TOML or JSON users file (name, role, scrypt hash) and checks passwords on a worker thread.
  An unknown user and a wrong password cost the same. The file is read again when it changes.
  `UserManager.authenticate` is the awaitable form of `get_user`, which stays for existing managers; a manager without
  `authenticate` keeps working (SRV-101).
- Commands: `enginir-opcua init server|client DIR`, `trust THUMBPRINT_OR_FILE [--pki DIR]`, `pki list`, `pair
  SERVER_PKI CLIENT_PKI` (development only, always warns), `user add|list|remove FILE`; `server --config FILE` serves
  from a configuration file. `RESERVED_COMMANDS` in `enginir_opcua.tools` is removed.
- Trust errors name the fix. The server log says `client certificate <thumbprint> (...) rejected: it is not trusted;
  trust it with: enginir-opcua trust <thumbprint> --pki <dir>` (once per certificate and ten minutes); the exception
  of a client that refuses a server certificate says the same for the server certificate, and a refused secure channel
  names the client certificate that the server probably does not trust. A server certificate that the endpoint list
  offered and the trust store does not trust is kept in `rejected/certs`, and the client keeps it there before it
  raises (CLI-72, CLI-73, CRY-33).
- A running server or client reads the trust lists again when a certificate is refused and `trusted/certs` changed, at
  most once per second (`TrustStore.refresh_interval`), and `enginir-opcua trust` reloads the stores of its own process
  (SRV-102). `TrustStore.load_blocking()` and `refresh_if_changed()` are new.
- `Server.set_endpoint` refuses a URL without the `opc.tcp` scheme, host or a valid port, and `set_security_policy([])`
  and `set_identity_tokens([])` raise `ConfigurationError` (SRV-103, SRV-104). A development-profile server refuses a
  `socket_address` that is not loopback (SRV-105).
- A private key that the PKI directory generates is encrypted when a password is given (CRY-32). The default client
  name is `engiNIR OPC UA Client` (CLI-71).

Examples (workstream K):
- The inherited `examples/` directory is removed with everything in it, including the keys and certificates that were
  committed there (they remain in the history). The new set is 16 files, `01_secure_pair.py` to
  `16_reverse_connect.py`, one per task: the quick-setup pair, users and roles, subscriptions with reconnect, methods,
  custom types, events and history, an instrument server from the DI and ADI models, file transfer, an HA client,
  PubSub, the sync API, a limit alarm, diagnostics, certificate management over OPC UA, the development profile and
  reverse connect.
- Each example uses a temporary PKI directory and generates its certificates, pairs the two sides in code, ends by
  itself and prints `OK <name>`. Only `15_development_profile.py` uses NoSecurity, on 127.0.0.1. `tests/examples/`
  runs every example as a subprocess (marked `slow`).
- The Quick Setup page (`docs/usage/get-started/quick-setup.rst`) describes the profiles, configuration files, the users
  file and the `init`, `trust`, `pki`, `pair` and `user` commands, and lists the examples. The minimal server and client
  pages and the README quick start use `Server.quickstart` and `Client.quickstart`.

API freeze (before 3.0.0rc1):
- `Client.init_pki()` and `Server.init_pki()` (and the sync twins) create the PKI directory and the self-signed
  application certificate of a quick-setup object before the first `connect()` or `init()` and return the certificate;
  calling them again returns the same one. A program that pairs a client and a server in code no longer needs
  `pki.create_directories` and `pki.load_own_credentials` (CLI-84).
- `sync.Server.quickstart` and `sync.Client.quickstart` take `tloop=None`, so a quick-setup server and client can share
  one `ThreadLoop` (CLI-85). `examples/11_sync.py` does.
- `HaClient.quickstart(urls, profile="secure", pki="./pki", username=None, password=None, **overrides)` builds an HA
  client whose clients are configured like `Client.quickstart`: one PKI directory, the host-derived ApplicationUri (or
  `application_uri=`), the profile's security, and the trust store of the PKI directory. The overrides are `HaConfig`
  fields and any other `ClientConfig` field. `HaSecurityConfig` has the new fields `pki`, `profile`, `application_uri`
  and `client_settings`; `HaClient.init_pki()` creates the shared certificate before `start()` (which does it too) and
  `HaClient.config` returns the `HaConfig`. The constructor with explicit certificates is unchanged. `examples/09_ha_client.py`
  uses it without private attributes (CLI-83).
- `sync.SyncCondition` wraps the server's `Condition` handle (activate, deactivate, update_value, acknowledge, confirm,
  add_comment, the shelve calls, set_limits and the state properties). `sync.Server.create_condition`, `get_condition`,
  `conditions`, `delete_condition` and `refresh_required` exist now; the sync twin check no longer excludes them, and it
  covers `Condition`.
