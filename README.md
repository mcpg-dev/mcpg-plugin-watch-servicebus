# Azure Service Bus Watch Strategy — `dev.mcpg.watch.servicebus`

> class `watch_strategy` · `native` · package `mcpg-plugin-watch-servicebus` · artifact `libmcpg_plugin_watch_servicebus.so` · Apache-2.0

Consumes an Azure Service Bus queue or topic subscription, or the
dead-letter queue of either, as MCP Events. The `servicebus_entity`
strategy receives over AMQP 1.0 in peek-lock mode, and each message is one
`servicebus.message` event:

- A message is **completed** once the gateway has stored its event, and only
  then.
- A message the gateway has not acknowledged in `ack_timeout_ms` is
  **abandoned**, so it comes back: delivery is at-least-once. An abandon
  counts as a delivery, so a message the gateway never takes reaches the
  dead-letter queue after the entity's `MaxDeliveryCount`.
- The broker's sequence number is the event id, so the gateway stores a
  redelivered message once.
- The message's **lock is renewed** at half its span while the gateway has
  it, so a lock shorter than `ack_timeout_ms` does not hand the message to
  another receiver.
- A message whose link is gone, after a reconnect, is settled through the
  entity's `$management` node by its lock token.
- When the watch stops, the messages it holds are abandoned at once.

## Configuration

```yaml
plugins:
  - id: dev.mcpg.watch.servicebus
    class: watch_strategy
    kind: native
    source: { oci: "<registry>/plugins/watch-servicebus:protocol-1" }

mcp:
  configurations:
    events:
      enabled: true
      store: { kind: file, dir: /var/lib/mcpg/events/subscriptions }
      log_store: { kind: file, dir: /var/lib/mcpg/events/log }
  capabilities:
    events:
      - name: orders.placed
        description: An order message on the orders queue.
        source:
          watch:
            strategy:
              type: plugin
              kind: servicebus_entity
              namespace: acme.servicebus.windows.net
              credential: { type: workload_identity }
              queue: orders
            event_type: servicebus.message
```

A topic subscription takes `topic` and `subscription` in place of `queue`.
With a connection string the namespace and the key come from it:

```yaml
strategy:
  type: plugin
  kind: servicebus_entity
  connection_string: ${secret.ORDERS_LISTEN}
  topic: orders
  subscription: gateway
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `connection_string` | string | — | `Endpoint=sb://…;SharedAccessKeyName=…;SharedAccessKey=…`, or with `SharedAccessSignature=…`. Its `EntityPath`, when set, names the queue or topic. `UseDevelopmentEmulator=true` connects to the emulator over plain AMQP. |
| `namespace` | string | — | The fully qualified namespace, `<name>.servicebus.windows.net`. Give it or `connection_string`, not both. |
| `credential` | object | — | Required with `namespace`; see below. |
| `queue` | string | — | The queue to read. |
| `topic`, `subscription` | string | — | The subscription to read. |
| `sub_queue` | `dead_letter` \| `transfer_dead_letter` | — | Read the entity's dead-letter queue, or its transfer dead-letter queue, instead. |
| `sessions` | bool | `false` | The entity requires sessions: take each session the broker offers, one at a time. |
| `session_id` | string | — | The entity requires sessions: take this one session only. |
| `receive_wait_secs` | int | `10` | Longest one receive waits for a message (1 to 20). |
| `max_in_flight` | int | `256` | Most messages received and not yet settled (1 to 1000). |
| `ack_timeout_ms` | int | `60000` | How long a message waits for the gateway before it is abandoned. |
| `max_body_bytes` | int | `131072` | A larger body is left out of the event, with `bodyTruncated: true` and `bodySize` (at most 196608). |

`credential.type` is one of:

| Type | Fields | Notes |
|---|---|---|
| `shared_access_key` | `key_name`, `key` | A shared access policy; the watch signs its own tokens with it, valid one hour and renewed before they expire. |
| `shared_access_signature` | `signature` | A ready `SharedAccessSignature sr=…&sig=…&se=…&skn=…`. It is used until its `se` and not renewed. |
| `client_secret` | `tenant_id`, `client_id`, `client_secret` | An Entra ID application. |
| `workload_identity` | `tenant_id`, `client_id`, `token_file` (all optional) | A Kubernetes service account federated with Entra ID; each field defaults to the `AZURE_*` variable the workload identity webhook sets (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`). The token file must exist when the watch starts, or the watch does not start. The watch reads the file again when its copy is more than 10 minutes old. |
| `managed_identity` | one of `client_id`, `object_id`, `resource_id` (optional) | The host's managed identity: the system-assigned one, or the user-assigned one named. See [Managed identity sources](#managed-identity-sources). |

Secrets are resolved before the watch starts (`${env.X}`, `${secret.X}`,
`vault://…`); `cred://` is rejected. An Entra ID identity needs the **Azure
Service Bus Data Receiver** role on the entity; a shared access policy needs
the **Listen** right. `AZURE_AUTHORITY_HOST` selects a sovereign cloud's
Entra ID.

### Managed identity sources

When the watch starts, it selects the managed identity source from the
gateway's environment. The first row that matches applies:

| Environment | Source | Supported |
|---|---|---|
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` and `IDENTITY_SERVER_THUMBPRINT` | `Service Fabric` | No |
| `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` | `App Service` | Yes. `resource_id` is refused (`User-assigned resource IDs aren't supported for App Service`): name a user-assigned identity by `client_id` or `object_id`. |
| `IDENTITY_ENDPOINT` and `IMDS_ENDPOINT` | `Azure Arc` | No |
| `MSI_ENDPOINT` and `MSI_SECRET`, and no `IDENTITY_ENDPOINT` | `Azure ML` | No |
| `MSI_ENDPOINT`, and no `IDENTITY_ENDPOINT` | `CloudShell` | No |
| Any other combination, for example none of these variables, or `IDENTITY_ENDPOINT` alone | `IMDS` (`169.254.169.254`): a VM, a VM scale set, an AKS node | Yes, with any of the three ids. |

A source that is not supported stops the watch start with this error,
where `<source>` is the name in the Source column:
`servicebus_entity: managed_identity: <source> managed identity isn't supported`.
For example, the error for the Cloud Shell source ends with
`CloudShell managed identity isn't supported`.

### Sessions

On a session-enabled entity the link holds one session at a time, and the
session's lock covers its messages: the watch renews the session lock while
it holds the session. With `sessions: true` it lets a session go once the
session has been idle for `receive_wait_secs` and nothing received from it
is still held, then takes the next session the broker offers. A busy
session therefore keeps the watch until it falls idle. With `session_id` the
watch holds that session and no other.

## Events

Each `servicebus.message` event's `data` is:

| Field | Meaning |
|---|---|
| `namespace`, `entity` | Where it came from: the namespace host, and the entity path, `orders` or `orders/Subscriptions/gateway`, with `/$DeadLetterQueue` for a dead-letter queue. |
| `sequenceNumber` | The broker's sequence number; the event id. |
| `messageId` | The sender's message id. |
| `body`, `bodyEncoding` | The body: its JSON when it parses, else its text, else base64 of its bytes. An AMQP value body other than text or binary is its JSON. |
| `bodyTruncated`, `bodySize` | Set when the body was over `max_body_bytes`. |
| `subject`, `contentType`, `correlationId`, `to`, `replyTo`, `sessionId`, `replyToSessionId`, `partitionKey` | The message's properties, when set. |
| `enqueuedAt` | When the broker took it, RFC 3339; also the event time. |
| `scheduledEnqueueAt`, `expiresAt` | When it was scheduled for, and when it expires. |
| `deliveryCount` | Which delivery of the message this is, from 1. |
| `deadLetterReason`, `deadLetterErrorDescription`, `deadLetterSource` | Set on a message read from a dead-letter queue. |
| `applicationProperties` | Each application property by name; timestamps as RFC 3339, binary as base64. |

## Build / test

```bash
cargo build  -p mcpg-plugin-watch-servicebus
cargo test   -p mcpg-plugin-watch-servicebus                              # unit tests
cargo clippy -p mcpg-plugin-watch-servicebus --all-targets -- -D warnings
```

The unit tests send the Entra ID token requests of `client_secret`,
`workload_identity` and `managed_identity` through a recording HTTP client,
with no network. The IMDS request is in its own suite,
`tests/servicebus_imds.rs`, without a test harness: the managed identity
source comes from the process environment, which that suite sets before any
thread starts.

The integration suite runs against the
[Service Bus emulator](https://learn.microsoft.com/azure/service-bus-messaging/overview-emulator),
which needs SQL Server beside it and the entities in
[`emulator-config.json`](emulator-config.json). Start both as the
emulator's documentation shows, with that file as its `Config.json`, then:

```bash
SERVICEBUS_TEST_CONNECTION_STRING='Endpoint=sb://localhost:5672;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=SAS_KEY_VALUE;UseDevelopmentEmulator=true;' \
  cargo test -p mcpg-plugin-watch-servicebus --features integration-tests
```

It runs the watch through a window, an acknowledgement, an abandon and the
redelivery after the timeout, a release on cancel, a lock held past its
duration, settling after the connection was cut, a dead-letter queue, a
topic subscription, and session-enabled queues. The tests take turns, since
the emulator caps the connections it accepts. Within one `cargo test`
process a lock gives the turns. `cargo nextest run` runs each test in its
own process, where that lock does not reach, so it must run this suite one
test at a time: `--test-threads 1`, or a nextest test group with
`max-threads = 1` for the `servicebus_emulator` binary.

Before the watch's session test, a control holds a session lock for 12
seconds with no renewal and then completes the message. On Azure the broker
lapses the lock and does not take the late completion, so the message comes
back. The control asserts that the message comes back, and only logs the
result of the completion call. The emulator is not the service, so there
the control only logs whether the lock lapsed. Without that control, a pass
of the session test does not show that renewal works. The control runs once
in each process, so under nextest it runs in its own test and again before
the session test.

### Running against Azure

CI does not run this. It costs money while the namespace exists, so delete
the resource group when you are done.

The suite connects over TLS on port 5671 to any namespace whose connection
string does not have `UseDevelopmentEmulator=true`. It needs the entities of
`emulator-config.json` with the same properties. The test client sends its
messages with `SERVICEBUS_TEST_CONNECTION_STRING`, so its policy has the
**Send** right as well as **Listen**. The watches connect with
`SERVICEBUS_TEST_WATCH_CONNECTION_STRING`, from a policy with **Listen**
only, so a run shows that the watch needs no more. The reconnect test is
skipped: TLS through its loopback proxy fails the host name check.

The scripts need the az CLI signed in (`az login`) with the target
subscription selected (`az account set --subscription <id>`), and `jq` and
`openssl`.

```bash
RG=mcpg-servicebus-test
LOCATION=westeurope
NS="mcpg-sb-test-$(openssl rand -hex 4)"

az group create --name "$RG" --location "$LOCATION"
az servicebus namespace create --resource-group "$RG" --name "$NS" \
  --location "$LOCATION" --sku Standard

# name, lock duration, max delivery count, requires session
queue() {
  az servicebus queue create --resource-group "$RG" --namespace-name "$NS" \
    --name "$1" --lock-duration "$2" --max-delivery-count "$3" \
    --enable-session "$4" --default-message-time-to-live PT1H \
    --duplicate-detection-history-time-window PT20S \
    --enable-duplicate-detection false \
    --enable-dead-lettering-on-message-expiration false
}
queue mcpg.window      PT1M 10 false
queue mcpg.renew       PT5S 10 false
queue mcpg.reconnect   PT5S 10 false
queue mcpg.deadletter  PT1M 1  false
queue mcpg.sessions    PT5S 10 true
queue mcpg.session-one PT1M 10 true

az servicebus topic create --resource-group "$RG" --namespace-name "$NS" \
  --name mcpg.events --default-message-time-to-live PT1H \
  --duplicate-detection-history-time-window PT20S \
  --enable-duplicate-detection false
az servicebus topic subscription create --resource-group "$RG" \
  --namespace-name "$NS" --topic-name mcpg.events --name gateway \
  --lock-duration PT1M --max-delivery-count 10 \
  --default-message-time-to-live PT1H --enable-session false \
  --enable-dead-lettering-on-message-expiration false

az servicebus namespace authorization-rule create --resource-group "$RG" \
  --namespace-name "$NS" --name mcpg-test --rights Listen Send
export SERVICEBUS_TEST_CONNECTION_STRING="$(
  az servicebus namespace authorization-rule keys list --resource-group "$RG" \
    --namespace-name "$NS" --name mcpg-test \
    --query primaryConnectionString --output tsv)"

az servicebus namespace authorization-rule create --resource-group "$RG" \
  --namespace-name "$NS" --name mcpg-watch --rights Listen
export SERVICEBUS_TEST_WATCH_CONNECTION_STRING="$(
  az servicebus namespace authorization-rule keys list --resource-group "$RG" \
    --namespace-name "$NS" --name mcpg-watch \
    --query primaryConnectionString --output tsv)"
```

For an Entra ID run, also make an app registration with a client secret and
the **Azure Service Bus Data Receiver** role on the namespace. The watches
then connect with `namespace` and `credential` in place of
`SERVICEBUS_TEST_WATCH_CONNECTION_STRING`, and the test client still sends
with `SERVICEBUS_TEST_CONNECTION_STRING`. The role assignment can take a few
minutes to apply.

```bash
SCOPE="$(az servicebus namespace show --resource-group "$RG" --name "$NS" \
  --query id --output tsv)"
APP="$(az ad sp create-for-rbac --display-name "$NS-receiver" \
  --role "Azure Service Bus Data Receiver" --scopes "$SCOPE" --output json)"
APP_ID="$(jq -r .appId <<<"$APP")"
export SERVICEBUS_TEST_NAMESPACE="$NS.servicebus.windows.net"
export SERVICEBUS_TEST_CREDENTIAL="$(jq -c '{type: "client_secret",
  tenant_id: .tenant, client_id: .appId, client_secret: .password}' <<<"$APP")"
unset APP
```

Run the suite. The tests take turns, so one run takes several minutes. The
first test prints which connection the watches use:

```bash
cargo test -p mcpg-plugin-watch-servicebus --features integration-tests \
  --test servicebus_emulator -- --nocapture
```

Clean up. The app registration is not in the resource group, so delete it
separately. The variables hold the policy keys and the client secret:

```bash
az group delete --name "$RG" --yes
az ad app delete --id "$APP_ID"   # only after an Entra ID run
unset SERVICEBUS_TEST_CONNECTION_STRING SERVICEBUS_TEST_WATCH_CONNECTION_STRING \
  SERVICEBUS_TEST_NAMESPACE SERVICEBUS_TEST_CREDENTIAL
```
