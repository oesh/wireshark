#!/bin/bash
SCAFFOLD_NAME=$(basename $0)
function run_scaffold() {
	if echo ${SCAFFOLD_NAME} | grep "debug" ; then
		echo "d: lldb ${TSHARK} -- $@"
		lldb ${TSHARK} -- "$@"
	elif echo ${SCAFFOLD_NAME} | grep "verify" ; then 
		echo "v: ${TSHARK} $@"	
	else 
		echo "r: ${TSHARK} $@"	
		${TSHARK} "$@"
	fi
}


TESTNAME=$1
shift

TEST_BASEDIR=$(pwd)/${TESTNAME}
if [ -d "${TEST_BASEDIR}" ]; then 
	echo "Test name:            ${TESTNAME}"
	echo "Test base dir:        ${TEST_BASEDIR}"
else
	echo "Test base dir         ${TEST_BASEDIR} does not exist; exiting"
	exit 1 
fi

TLS_KEYLOG_FILE=${TEST_BASEDIR}/keylog.txt 
if [ -r "${TLS_KEYLOG_FILE}" ]; then 
	echo "TLS keylog file:      ${TLS_KEYLOG_FILE}"
else
	echo "TLS keylog file       ${TLS_KEYLOG_FILE} does not exist; exiting"
	exit 2
fi

TEST_INPUT_PCAP_FILE=${TEST_BASEDIR}/input.pcap
if [ -r "${TEST_INPUT_PCAP_FILE}" ]; then 
	echo "Test input PCAP file: ${TEST_INPUT_PCAP_FILE}"
else
	echo "Test input PCAP file  ${TEST_INPUT_PCAP_FILE} does not exit; exiting"
	exit 3
fi

LOGDIR="$(pwd)/logs"
mkdir -p ${LOGDIR}

TLS_DEBUG_FILE=$(mktemp ${LOGDIR}/${TESTNAME}.tls.debug.log.XXXX)
        echo "TLS debug log:        ${TLS_DEBUG_FILE}"
	
TSHARK=../build/run/tshark
if [ -x "${TSHARK}" ] ; then 
	echo "Tshark binary:        ${TSHARK}"
else
	echo "Tshark binary         ${TSHARK} does not exist; exiting"
	exit 4
fi

run_scaffold -r ${TEST_INPUT_PCAP_FILE} -otls.keylog_file:${TLS_KEYLOG_FILE} -otls.debug_file:${TLS_DEBUG_FILE} "$@"
