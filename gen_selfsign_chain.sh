#!/bin/bash

DN_COMMON_NAME="$(hostname)"
DN_COUNTRY=
DN_STATE=
DN_LOCALITY=
DN_ORGANIZATION=
DN_ORGANIZATION_UNIT=
DN_EMAIL=

ALT_NAMES=

KEY_TYPE='ec'
ROOT_CA_NAME="${DN_COMMON_NAME}"
INTERMEDIATE_CA_NAME="${DN_COMMON_NAME}"

BASE_DIR=
ROOT_CA_DIR=
INTERMEDIATE_CA_DIR=
SERVERS_DIR=

function f_trim
{
 printf "$*" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

function f_validate
{
  if [[ -z "${DN_COMMON_NAME}" ]]; then
    echo "Common name not specified!" >&2
    exit 2
  fi
  
  DOMAIN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]$'
  if [[ -n "$(echo "${DN_COMMON_NAME}" | grep '\.')" ]] && [[ ! "${DN_COMMON_NAME}" =~ ${DOMAIN_REGEX} ]]; then
    echo "ERROR! Invalid common name. ${DN_COMMON_NAME}" >&2
    exit 3
  fi
  
  if [[ -n "${DN_COUNTRY}" ]] && [[ "$(printf "${DN_COUNTRY}" | wc -m)" -ne 2 ]]; then
    echo "ERROR! Invalid country code. ${DN_COUNTRY}" >&2
    exit 4
  fi
  
  EMAIL_REGEX='^[a-zA-Z0-9]+([\._\-][a-zA-Z0-9]+)*@([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]$'
  if [[ -n "${DN_EMAIL}" ]] && [[ ! "${DN_EMAIL}" =~ ${EMAIL_REGEX} ]]; then
    echo "ERROR! Invalid email address. ${DN_EMAIL}" >&2
    exit 5
  fi
  
  SAN_REGEX='^(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9],)*([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]$'
  if [[ -n "${ALT_NAMES}" ]] && [[ ! "${ALT_NAMES}" =~ ${SAN_REGEX} ]]; then
    echo "ERROR! Invalid alternative names. ${ALT_NAMES}" >&2
    exit 6
  fi
}

function f_gen_key
{
  if [[ "$KEY_TYPE" == "ec" ]]; then
    CURVE_NAME=secp384r1
    if [[ ! $2 == "ca" ]]; then
      CURVE_NAME=secp256r1
    fi
    openssl ecparam -name ${CURVE_NAME} -genkey -noout -out "$1"
  else
    KEY_BITS=4096
    if [[ ! $2 == "ca" ]]; then
      KEY_BITS=2048
    fi
    openssl genrsa -out "$1" ${KEY_BITS}
  fi
  chmod 400 "$1"
}

function f_gen_ca_root
{
  CONF_DIR="${ROOT_CA_DIR}/conf"
  KEYS_DIR="${ROOT_CA_DIR}/keys"
  REQS_DIR="${ROOT_CA_DIR}/reqs"
  CERTS_DIR="${ROOT_CA_DIR}/certs"
  
  mkdir -p "${CONF_DIR}"
  mkdir -p "${KEYS_DIR}"
  mkdir -p "${REQS_DIR}"
  mkdir -p "${CERTS_DIR}"
  mkdir -p "${ROOT_CA_DIR}/newcerts"
  mkdir -p "${ROOT_CA_DIR}/crl"
  
  chmod 700 "${KEYS_DIR}"
  
  touch "${ROOT_CA_DIR}/index.txt"
  
  echo 1000 > "${ROOT_CA_DIR}/serial.txt"
  
  cat <<EOF > "${CONF_DIR}/${ROOT_CA_NAME}.conf"
[ ca ]
default_ca = ca_default

[ ca_default ]
dir              = ${ROOT_CA_DIR}
certs            = \$dir/certs
crl_dir          = \$dir/crl
new_certs_dir    = \$dir/newcerts
database         = \$dir/index.txt
serial           = \$dir/serial.txt
RANDFILE         = \$dir/keys/.rand
private_key      = \$dir/keys/${ROOT_CA_NAME}.key
certificate      = \$dir/certs/${ROOT_CA_NAME}.crt
crlnumber        = \$dir/crlnumber.txt
crl              = \$dir/crl/${ROOT_CA_NAME}.crl
crl_extensions   = crl_ext
default_crl_days = 30
default_md       = sha384
name_opt         = ca_default
cert_opt         = ca_default
default_days     = 3653
preserve         = no
policy           = ca_policy
copy_extensions  = copy
prompt           = no

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ ca_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
default_bits       = 4096
distinguished_name = dn
string_mask        = utf8only
default_md         = sha384
req_extensions     = req_ext
prompt             = no

[ dn ]
countryName            = ${DN_COUNTRY}
stateOrProvinceName    = ${DN_STATE}
localityName           = ${DN_LOCALITY}
organizationName       = ${DN_ORGANIZATION}
organizationalUnitName = ${DN_ORGANIZATION_UNIT}
commonName             = ${ROOT_CA_NAME} Root Certificate Authority
emailAddress           = ${DN_EMAIL}

[ req_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ ocsp ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF

  sed -i '/= $/d' "${CONF_DIR}/${ROOT_CA_NAME}.conf"

  f_gen_key "${KEYS_DIR}/${ROOT_CA_NAME}.key" "ca"

  openssl req -new -x509 -config "${CONF_DIR}/${ROOT_CA_NAME}.conf" -days 3653 -sha384 -key "${KEYS_DIR}/${ROOT_CA_NAME}.key" -extensions req_ext -out "${CERTS_DIR}/${ROOT_CA_NAME}.crt"
  
  chmod 444 "${CERTS_DIR}/${ROOT_CA_NAME}.crt"
}

function f_gen_ca_intermediate
{
  CONF_DIR="${INTERMEDIATE_CA_DIR}/conf"
  KEYS_DIR="${INTERMEDIATE_CA_DIR}/keys"
  REQS_DIR="${INTERMEDIATE_CA_DIR}/reqs"
  CERTS_DIR="${INTERMEDIATE_CA_DIR}/certs"
  
  mkdir -p "${CONF_DIR}"
  mkdir -p "${KEYS_DIR}"
  mkdir -p "${REQS_DIR}"
  mkdir -p "${CERTS_DIR}"
  mkdir -p "${INTERMEDIATE_CA_DIR}/newcerts"
  mkdir -p "${INTERMEDIATE_CA_DIR}/crl"
  
  chmod 700 "${KEYS_DIR}"
  
  touch "${INTERMEDIATE_CA_DIR}/index.txt"
  
  echo 10000000 > "${INTERMEDIATE_CA_DIR}/serial.txt"
  
  cat <<EOF > "${CONF_DIR}/${INTERMEDIATE_CA_NAME}.conf"
[ ca ]
default_ca = ca_default

[ ca_default ]
dir              = ${INTERMEDIATE_CA_DIR}
certs            = \$dir/certs
crl_dir          = \$dir/crl
new_certs_dir    = \$dir/newcerts
database         = \$dir/index.txt
serial           = \$dir/serial.txt
RANDFILE         = \$dir/keys/.rand
private_key      = \$dir/keys/${INTERMEDIATE_CA_NAME}.key
certificate      = \$dir/certs/${INTERMEDIATE_CA_NAME}.crt
crlnumber        = \$dir/crlnumber.txt
crl              = \$dir/crl/${INTERMEDIATE_CA_NAME}.crl
crl_extensions   = crl_ext
default_crl_days = 30
default_md       = sha384
name_opt         = ca_default
cert_opt         = ca_default
default_days     = 1827
preserve         = no
policy           = ca_policy
copy_extensions  = copy
prompt           = no

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ ca_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
default_bits       = 4096
distinguished_name = dn
string_mask        = utf8only
default_md         = sha384
req_extensions     = req_ext
prompt             = no

[ dn ]
countryName            = ${DN_COUNTRY}
stateOrProvinceName    = ${DN_STATE}
localityName           = ${DN_LOCALITY}
organizationName       = ${DN_ORGANIZATION}
organizationalUnitName = ${DN_ORGANIZATION_UNIT}
commonName             = ${INTERMEDIATE_CA_NAME} Intermediate Certificate Authority
emailAddress           = ${DN_EMAIL}

[ req_ext ]
subjectKeyIdentifier   = hash
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ ocsp ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF

  sed -i '/= $/d' "${CONF_DIR}/${INTERMEDIATE_CA_NAME}.conf"

  f_gen_key "${KEYS_DIR}/${INTERMEDIATE_CA_NAME}.key" "ca"
  
  openssl req -new -sha384 -config "${CONF_DIR}/${INTERMEDIATE_CA_NAME}.conf" -key "${KEYS_DIR}/${INTERMEDIATE_CA_NAME}.key" -out "${REQS_DIR}/${INTERMEDIATE_CA_NAME}.csr"
  chmod 444 "${REQS_DIR}/${INTERMEDIATE_CA_NAME}.csr"
  
  openssl ca -batch -days 1827 -notext -md sha384 -config "${ROOT_CA_DIR}/conf/${ROOT_CA_NAME}.conf" -in "${REQS_DIR}/${INTERMEDIATE_CA_NAME}.csr" -out "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.crt"
  chmod 444 "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.crt"
  
  cat "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.crt" "${ROOT_CA_DIR}/certs/${ROOT_CA_NAME}.crt" > "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.chain.crt"
  chmod 444 "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.chain.crt"
  
  cp -p "${CERTS_DIR}/${INTERMEDIATE_CA_NAME}.chain.crt" "${BASE_DIR}/${INTERMEDIATE_CA_NAME}.ca.crt"
}

function f_gen_cert_server
{
  CONF_DIR="${SERVERS_DIR}/conf"
  KEYS_DIR="${SERVERS_DIR}/keys"
  REQS_DIR="${SERVERS_DIR}/reqs"
  CERTS_DIR="${SERVERS_DIR}/certs"
  
  mkdir -p "${CONF_DIR}"
  mkdir -p "${KEYS_DIR}"
  mkdir -p "${REQS_DIR}"
  mkdir -p "${CERTS_DIR}"
  
  rm -f "${KEYS_DIR}/${DN_COMMON_NAME}.key" "${REQS_DIR}/${DN_COMMON_NAME}.csr" "${CERTS_DIR}/${DN_COMMON_NAME}.crt" "${CERTS_DIR}/${DN_COMMON_NAME}.chain.crt"
  
  cat <<EOF > "${CONF_DIR}/${DN_COMMON_NAME}.conf"
[ req ]
default_bits       = 2048
distinguished_name = dn
string_mask        = utf8only
default_md         = sha256
req_extensions     = req_ext
prompt             = no

[ dn ]
countryName            = ${DN_COUNTRY}
stateOrProvinceName    = ${DN_STATE}
localityName           = ${DN_LOCALITY}
organizationName       = ${DN_ORGANIZATION}
organizationalUnitName = ${DN_ORGANIZATION_UNIT}
commonName             = ${DN_COMMON_NAME}
emailAddress           = ${DN_EMAIL}

[ req_ext ]
basicConstraints       = CA:FALSE
nsCertType             = server
subjectKeyIdentifier   = hash
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @san

[ san ]
DNS.0 = ${DN_COMMON_NAME}
${ALT_NAMES}
EOF

  sed -i '/= $/d' "${CONF_DIR}/${DN_COMMON_NAME}.conf"

  f_gen_key "${KEYS_DIR}/${DN_COMMON_NAME}.key"
  
  openssl req -sha256 -new -config "${CONF_DIR}/${DN_COMMON_NAME}.conf" -key "${KEYS_DIR}/${DN_COMMON_NAME}.key" -out "${REQS_DIR}/${DN_COMMON_NAME}.csr"
  chmod 444 "${REQS_DIR}/${DN_COMMON_NAME}.csr"
  
  openssl ca -batch -days 366 -notext -md sha256 -config "${INTERMEDIATE_CA_DIR}/conf/${INTERMEDIATE_CA_NAME}.conf" -in "${REQS_DIR}/${DN_COMMON_NAME}.csr" -out "${CERTS_DIR}/${DN_COMMON_NAME}.crt"
  chmod 444 "${CERTS_DIR}/${DN_COMMON_NAME}.crt"
  
  cat "${CERTS_DIR}/${DN_COMMON_NAME}.crt" "${INTERMEDIATE_CA_DIR}/certs/${INTERMEDIATE_CA_NAME}.chain.crt" > "${CERTS_DIR}/${DN_COMMON_NAME}.chain.crt"
  chmod 444 "${CERTS_DIR}/${DN_COMMON_NAME}.chain.crt"
  
  cp -p "${KEYS_DIR}/${DN_COMMON_NAME}.key" "${BASE_DIR}/${DN_COMMON_NAME}.key"
  cp -p "${CERTS_DIR}/${DN_COMMON_NAME}.chain.crt" "${BASE_DIR}/${DN_COMMON_NAME}.crt"
}

if [[ $# -gt 0 ]]; then
  while :; do
    case $1 in
      -cn)
        shift
        DN_COMMON_NAME="$(f_trim "$1")"
      ;;
      -c)
        shift
        DN_COUNTRY="$(f_trim "$1")"
      ;;
      -s)
        shift
        DN_STATE="$(f_trim "$1")"
      ;;
      -l)
        shift
        DN_LOCALITY="$(f_trim "$1")"
      ;;
      -o)
        shift
        DN_ORGANIZATION="$(f_trim "$1")"
      ;;
      -ou)
        shift
        DN_ORGANIZATION_UNIT="$(f_trim "$1")"
      ;;
      -e)
        shift
        DN_EMAIL="$(f_trim "$1")"
      ;;
      -kt)
        shift
        KEY_TYPE="$(f_trim "$1")"
      ;;
      -rca)
        shift
        ROOT_CA_NAME="$(f_trim "$1")"
      ;;
      -ica)
        shift
        INTERMEDIATE_CA_NAME="$(f_trim "$1")"
      ;;
      -san)
        shift
        ALT_NAMES="$(f_trim "$1")"
      ;;
      *)
        if [ -n "$1" ]; then
          echo "ERROR! Invalid paramter. $1" >&2
          exit 1
        fi
        break
      ;;
    esac
    shift
  done
fi

f_validate

DN_COUNTRY="$(echo "${DN_COUNTRY}" | tr '[:lower:]' '[:upper:]')"
ALT_NAMES="$(echo "${ALT_NAMES}" | awk -F',' '{for(i=1;i<=NF;i++){print "DNS."(i+1)" = "$i}}')"

BASE_DIR="$(readlink -f "$(dirname $0)")/${ROOT_CA_NAME}"
ROOT_CA_DIR="${BASE_DIR}/ca/root"
INTERMEDIATE_CA_DIR="${BASE_DIR}/ca/intermediate"
SERVERS_DIR="${BASE_DIR}/ca/servers"

if [[ -f "${BASE_DIR}/${DN_COMMON_NAME}.crt" ]]; then
  echo "ERROR! Server certificate already exists. ${DN_COMMON_NAME}" >&2
  exit 7
fi

echo '##### Started #####'

if [[ ! -d "${ROOT_CA_NAME}" ]]; then
  mkdir -p "${BASE_DIR}"
  echo "##### Generate Root CA - ${ROOT_CA_NAME} #####"
  f_gen_ca_root
  
  echo "##### Generate Intermediate CA - ${INTERMEDIATE_CA_NAME} #####"
  f_gen_ca_intermediate
  
  echo '##### Verify CA certs #####'
  openssl verify -show_chain -CAfile "${BASE_DIR}/${INTERMEDIATE_CA_NAME}.ca.crt" "${BASE_DIR}/${INTERMEDIATE_CA_NAME}.ca.crt"
fi

echo "##### Generate server key and certificate - ${DN_COMMON_NAME} #####"
f_gen_cert_server

echo '##### Verify server certificate #####'
openssl verify -show_chain -CAfile "${BASE_DIR}/${INTERMEDIATE_CA_NAME}.ca.crt" "${BASE_DIR}/${DN_COMMON_NAME}.crt"

echo '##### Finished #####'
