exports.handler = (event, context) => {
  const { body } = event;

  const type_index = body.indexOf("type=") + "type=".length;
  const type = body.slice(type_index, body.indexOf(" ", type_index));

  const msg_index = body.indexOf("msg=") + "msg=".length;
  const msg = body.slice(msg_index, body.length);

  const hirez_index = msg.indexOf("(") + "(".length;
  const hirez = msg.slice(hirez_index, msg.indexOf(":"));

  const auid_index = msg.indexOf(":") + ":".length;
  const auid = msg.slice(auid_index, msg.indexOf(")"));

  const audit_parts = msg
    .slice(msg.indexOf(":", auid_index) + ":".length)
    .trim()
    .split(" ")
    .reduce((acc, line_part) => {
      const [key, value] = line_part.split("=");
      return { [key]: value, ...acc };
    }, {});

  return { type, msg, hirez, auid, audit_parts };
};
