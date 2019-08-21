const fs = require("fs");

const { expect } = require("chai");
const { handler } = require("../index.js");

describe("audit log parsing", function() {
  describe("#handler()", function() {
    it("should parse cwd audit message", function(done) {
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
      done();
    });
  });
});
