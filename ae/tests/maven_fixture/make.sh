#!/bin/sh
# Regenerates the fixture Maven repository under repo/ and the trusted and
# untrusted fixture keys under keys/ (public halves only; the private keys
# live in a temporary GNUPGHOME and are gone afterwards). Needs gpg and a
# JDK (JAVA_HOME, default /opt/homebrew/opt/openjdk@21). Nothing here
# reaches a network. The tests serve repo/ from 127.0.0.1 with the
# Last-Modified dates they choose; the files themselves carry no dates.
#
# Artifacts (groupId invalid.naeb.fx):
#   parent:1.0 (pom)           the project's parent; manages lib-b
#   bom:1.0 (pom)              imported BOM; manages lib-managed:1.3
#   lib-a:1.0 -> lib-b:1.0     a transitive dependency (lib-b's parent: parent)
#   lib-b:1.0                  signed by the Ed25519 key
#   lib-managed:1.3            version from the BOM only
#   lib-young:2.0              the tests serve it as published 2 days ago
#   lib-range:1.0,1.5,1.9,2.0  maven-metadata.xml; the tests serve 1.9 young
#   lib-badsum:1.0             its .sha1/.sha256 do not match the jar
#   lib-badsig:1.0             checksums match; the trusted key signed other bytes
#   lib-unknownkey:1.0         signed by a key not in the trusted keyring
#   lib-unreached:1.0          in the repository, in no project POM
#   fx-maven-plugin:1.0        a build extension whose class would create
#                              $NAEB_FX_MARKER if it were ever loaded
#   lib-elsewhere:1.0          only in repo-other/ (a repository naeb.ae does not allow)
#
# And org.apache.maven:apache-maven:3.9.16 (pom, bin.zip), a fake Maven
# distribution for the wrapper (project/mvnw, project/.mvn/wrapper): its
# bin/mvn only prints MAVEN_ARGS and its arguments. A stand-in, not Maven.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}
work=$(mktemp -d)
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
gpg -q --batch --passphrase '' --quick-gen-key "naeb fixture RSA <rsa@naeb.invalid>" rsa2048 sign never
gpg -q --batch --passphrase '' --quick-gen-key "naeb fixture Ed25519 <ed@naeb.invalid>" ed25519 sign never
gpg -q --batch --passphrase '' --quick-gen-key "naeb stranger <stranger@naeb.invalid>" rsa2048 sign never
rm -rf "$here/repo" "$here/repo-other" "$here/keys"
mkdir -p "$here/keys"
gpg -q --batch --armor --export "<rsa@naeb.invalid>" "<ed@naeb.invalid>" > "$here/keys/trusted.asc"
gpg -q --batch --armor --export "<stranger@naeb.invalid>" > "$here/keys/untrusted.asc"

G=invalid.naeb.fx
GP=invalid/naeb/fx

pom() {   # pom ARTIFACT VERSION PACKAGING BODY
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n%s  <groupId>%s</groupId>\n  <artifactId>%s</artifactId>\n  <version>%s</version>\n  <packaging>%s</packaging>\n</project>\n' "$4" "$G" "$1" "$2" "$3"
}

put() {   # put REPO ARTIFACT VERSION EXT CONTENT-FILE
    d="$1/$GP/$2/$3"
    mkdir -p "$d"
    f="$d/$2-$3.$4"
    cp "$5" "$f"
    shasum -a 1 "$f" | cut -c1-40 | tr -d '\n' > "$f.sha1"
    shasum -a 256 "$f" | cut -c1-64 | tr -d '\n' > "$f.sha256"
}

sign() {  # sign KEY FILE
    gpg -q --batch --yes --armor --detach-sign -u "$1" -o "$2.asc" "$2"
}

jar_of() {  # jar_of OUT TEXT
    mkdir -p "$work/j/META-INF"
    rm -rf "$work/j"/*
    mkdir -p "$work/j/META-INF"
    printf '%s\n' "$2" > "$work/j/META-INF/fixture.txt"
    (cd "$work/j" && "$JAVA_HOME/bin/jar" --create --file "$1" --no-manifest META-INF/fixture.txt)
}

artifact() {  # artifact REPO ARTIFACT VERSION KEY POM-BODY
    pom "$2" "$3" jar "$5" > "$work/p.pom"
    put "$1" "$2" "$3" pom "$work/p.pom"
    jar_of "$work/a.jar" "$2 $3"
    put "$1" "$2" "$3" jar "$work/a.jar"
    if [ -n "$4" ]; then
        sign "$4" "$1/$GP/$2/$3/$2-$3.pom"
        sign "$4" "$1/$GP/$2/$3/$2-$3.jar"
    fi
}

R="$here/repo"
dep() { printf '      <dependency><groupId>%s</groupId><artifactId>%s</artifactId>%s</dependency>\n' "$G" "$1" "${2:+<version>$2</version>}"; }
parent() { printf '  <parent><groupId>%s</groupId><artifactId>parent</artifactId><version>1.0</version></parent>\n' "$G"; }

pom parent 1.0 pom "  <properties><fx.b.version>1.0</fx.b.version></properties>
  <dependencyManagement><dependencies>
$(dep lib-b '${fx.b.version}')  </dependencies></dependencyManagement>
" > "$work/p.pom"
put "$R" parent 1.0 pom "$work/p.pom"
sign "<rsa@naeb.invalid>" "$R/$GP/parent/1.0/parent-1.0.pom"

pom bom 1.0 pom "  <dependencyManagement><dependencies>
$(dep lib-managed 1.3)  </dependencies></dependencyManagement>
" > "$work/p.pom"
put "$R" bom 1.0 pom "$work/p.pom"
sign "<rsa@naeb.invalid>" "$R/$GP/bom/1.0/bom-1.0.pom"

artifact "$R" lib-a 1.0 "<rsa@naeb.invalid>" "  <dependencies>
$(dep lib-b 1.0)$(printf '      <dependency><groupId>%s</groupId><artifactId>lib-test-only</artifactId><version>1.0</version><scope>test</scope></dependency>\n' "$G")  </dependencies>
"
artifact "$R" lib-b 1.0 "<ed@naeb.invalid>" "$(parent)"
artifact "$R" lib-managed 1.3 "<rsa@naeb.invalid>" ""
artifact "$R" lib-young 2.0 "<rsa@naeb.invalid>" ""
for v in 1.0 1.5 1.9 2.0; do artifact "$R" lib-range "$v" "<rsa@naeb.invalid>" ""; done
printf '<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n  <groupId>%s</groupId>\n  <artifactId>lib-range</artifactId>\n  <versioning>\n    <latest>2.0</latest>\n    <release>2.0</release>\n    <versions>\n      <version>1.0</version>\n      <version>1.5</version>\n      <version>1.9</version>\n      <version>2.0</version>\n    </versions>\n  </versioning>\n</metadata>\n' "$G" > "$work/m.xml"
cp "$work/m.xml" "$R/$GP/lib-range/maven-metadata.xml"
shasum -a 1 "$R/$GP/lib-range/maven-metadata.xml" | cut -c1-40 | tr -d '\n' > "$R/$GP/lib-range/maven-metadata.xml.sha1"

artifact "$R" lib-badsum 1.0 "<rsa@naeb.invalid>" ""
printf '%040d' 0 > "$R/$GP/lib-badsum/1.0/lib-badsum-1.0.jar.sha1"
printf '%064d' 0 > "$R/$GP/lib-badsum/1.0/lib-badsum-1.0.jar.sha256"

artifact "$R" lib-badsig 1.0 "" ""
jar_of "$work/other.jar" "not the published bytes"
gpg -q --batch --yes --armor --detach-sign -u "<rsa@naeb.invalid>" -o "$R/$GP/lib-badsig/1.0/lib-badsig-1.0.jar.asc" "$work/other.jar"
sign "<rsa@naeb.invalid>" "$R/$GP/lib-badsig/1.0/lib-badsig-1.0.pom"

artifact "$R" lib-unknownkey 1.0 "<stranger@naeb.invalid>" ""
artifact "$R" lib-unreached 1.0 "<rsa@naeb.invalid>" ""
artifact "$R" lib-test-only 1.0 "<rsa@naeb.invalid>" ""

# The extension: loading its class (Maven would, for <extensions>true</extensions>)
# writes the marker. naeb only ever reads its bytes.
mkdir -p "$work/ext/src/invalid/naeb/fx" "$work/ext/classes/META-INF/plexus"
cat > "$work/ext/src/invalid/naeb/fx/Marker.java" <<'JAVA'
package invalid.naeb.fx;

public final class Marker {
    static {
        try {
            String p = System.getenv("NAEB_FX_MARKER");
            if (p != null) java.nio.file.Files.writeString(java.nio.file.Path.of(p), "executed\n");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
JAVA
"$JAVA_HOME/bin/javac" --release 11 -d "$work/ext/classes" "$work/ext/src/invalid/naeb/fx/Marker.java"
printf '<component-set><components><component><role>org.apache.maven.AbstractMavenLifecycleParticipant</role><role-hint>fx</role-hint><implementation>invalid.naeb.fx.Marker</implementation></component></components></component-set>\n' > "$work/ext/classes/META-INF/plexus/components.xml"
(cd "$work/ext/classes" && "$JAVA_HOME/bin/jar" --create --file "$work/ext.jar" --no-manifest .)
pom fx-maven-plugin 1.0 maven-plugin "" > "$work/p.pom"
put "$R" fx-maven-plugin 1.0 pom "$work/p.pom"
put "$R" fx-maven-plugin 1.0 jar "$work/ext.jar"
sign "<rsa@naeb.invalid>" "$R/$GP/fx-maven-plugin/1.0/fx-maven-plugin-1.0.pom"
sign "<rsa@naeb.invalid>" "$R/$GP/fx-maven-plugin/1.0/fx-maven-plugin-1.0.jar"

artifact "$here/repo-other" lib-elsewhere 1.0 "<rsa@naeb.invalid>" ""

# The wrapper's distribution: apache-maven-3.9.16/ at the archive's top, as
# Maven's own -bin.zip has it.
MV=3.9.16
MD="$R/org/apache/maven/apache-maven/$MV"
mkdir -p "$MD" "$work/dist/apache-maven-$MV/bin" "$work/dist/apache-maven-$MV/conf" "$work/dist/apache-maven-$MV/lib"
printf '#!/bin/sh\necho "fixture maven %s: MAVEN_ARGS=${MAVEN_ARGS-} args=$*"\n' "$MV" > "$work/dist/apache-maven-$MV/bin/mvn"
printf '@echo fixture maven %s\r\n' "$MV" > "$work/dist/apache-maven-$MV/bin/mvn.cmd"
printf '<settings/>\n' > "$work/dist/apache-maven-$MV/conf/settings.xml"
printf 'a fixture, not Maven\n' > "$work/dist/apache-maven-$MV/lib/README"
chmod 755 "$work/dist/apache-maven-$MV/bin/mvn"
(cd "$work/dist" && zip -q -r -X "$work/dist.zip" "apache-maven-$MV")
printf '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>org.apache.maven</groupId>\n  <artifactId>apache-maven</artifactId>\n  <version>%s</version>\n  <packaging>pom</packaging>\n</project>\n' "$MV" > "$work/p.pom"
for f in "apache-maven-$MV.pom:$work/p.pom" "apache-maven-$MV-bin.zip:$work/dist.zip"; do
    name=${f%%:*}
    cp "${f#*:}" "$MD/$name"
    shasum -a 1 "$MD/$name" | cut -c1-40 | tr -d '\n' > "$MD/$name.sha1"
    shasum -a 512 "$MD/$name" | cut -c1-128 | tr -d '\n' > "$MD/$name.sha512"
    sign "<rsa@naeb.invalid>" "$MD/$name"
done
echo "fixture repository written under $here/repo"
