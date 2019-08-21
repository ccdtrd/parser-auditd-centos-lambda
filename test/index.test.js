const fs = require("fs");

const { expect } = require("chai");
const { handler } = require("../index.js");

describe("audit log parsing", () => {
  it("should parse CWD audit message", () => {
    const log = {
      body: `type=CWD msg=audit(1434371271.277:135496):  cwd="/home/sammy"`
    };
    const result = handler(log);
    expect(result).to.deep.equal({
      audit_parts: {
        cwd: '"/home/sammy"'
      },
      auid: "135496",
      hirez: "1434371271.277",
      msg: 'audit(1434371271.277:135496):  cwd="/home/sammy"',
      type: "CWD"
    });
  });

  it("should parse SYSCALL audit message", () => {
    const log = {
      body: `type=SYSCALL msg=audit(1434371271.277:135496): arch=c000003e syscall=2 success=yes exit=3 a0=7fff0054e929 a1=0 a2=1fffffffffff0000 a3=7fff0054c390 items=1 ppid=6265 pid=6266 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=113 comm="cat" exe="/usr/bin/cat" key="sshconfigchange"`
    };
    const result = handler(log);
    expect(result).to.deep.equal({
      audit_parts: {
        a0: "7fff0054e929",
        a1: "0",
        a2: "1fffffffffff0000",
        a3: "7fff0054c390",
        arch: "c000003e",
        auid: "1000",
        comm: '"cat"',
        egid: "0",
        euid: "0",
        exe: '"/usr/bin/cat"',
        exit: "3",
        fsgid: "0",
        fsuid: "0",
        gid: "0",
        items: "1",
        key: '"sshconfigchange"',
        pid: "6266",
        ppid: "6265",
        ses: "113",
        sgid: "0",
        success: "yes",
        suid: "0",
        syscall: "2",
        tty: "pts0",
        uid: "0"
      },
      auid: "135496",
      hirez: "1434371271.277",
      msg:
        'audit(1434371271.277:135496): arch=c000003e syscall=2 success=yes exit=3 a0=7fff0054e929 a1=0 a2=1fffffffffff0000 a3=7fff0054c390 items=1 ppid=6265 pid=6266 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=113 comm="cat" exe="/usr/bin/cat" key="sshconfigchange"',
      type: "SYSCALL"
    });
  });

  it("should parse PATH audit message", () => {
    const log = {
      body: `type=PATH msg=audit(1434371271.277:135496): item=0 name="/etc/ssh/sshd_config" inode=392210 dev=fd:01 mode=0100600 ouid=0 ogid=0 rdev=00:00 objtype=NORMAL`
    };
    const result = handler(log);
    expect(result).to.deep.equal({
      audit_parts: {
        dev: "fd:01",
        inode: "392210",
        item: "0",
        mode: "0100600",
        name: '"/etc/ssh/sshd_config"',
        objtype: "NORMAL",
        ogid: "0",
        ouid: "0",
        rdev: "00:00"
      },
      auid: "135496",
      hirez: "1434371271.277",
      msg:
        'audit(1434371271.277:135496): item=0 name="/etc/ssh/sshd_config" inode=392210 dev=fd:01 mode=0100600 ouid=0 ogid=0 rdev=00:00 objtype=NORMAL',
      type: "PATH"
    });
  });
});
