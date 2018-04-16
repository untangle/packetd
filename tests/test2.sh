#!/bin/sh

echo '{"foo": "bar"}' >| /etc/config/settings.json

# get orig data (should be above)
ORIGDATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $ORIGDATA | grep foo | grep -q bar ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# get just foo
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings/foo"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q bar ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# get an invalid settings
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings/aoeuaoeuaoue"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q error ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# get an invalid settings (recurse)
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings/xxxxx/aoeuaoeuaoue"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q error ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# set new settings
DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"xxx\": \"abc\"}' "http://localhost:8080/settings/set_settings"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi

# foo and bar should be gone, and xxx and abc should be there
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings/foo"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q bar ; then
    echo "Test FAIL"
else
    echo "Test pass"
fi
if echo $DATA | grep xxx | grep -q abc ; then
    echo "Test FAIL"
else
    echo "Test pass"
fi

# set just one attribute
DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '\"ddd\"' "http://localhost:8080/settings/set_settings/ccc"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi

# check data for ccc ddd
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep ccc | grep -q ddd ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# overwrite just one attribute
DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"sss\": \"ttt\"}' "http://localhost:8080/settings/set_settings/ccc"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi

# check data for ddd missing
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q ddd ; then
    echo "Test FAIL"
else
    echo "Test pass"
fi

# overwrite just one attribute
DATA="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d 'deepstring' "http://localhost:8080/settings/set_settings/a1/a2/a3"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi

# check data for deepstring
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings"`"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi
if echo $DATA | grep -q deepstring ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi

# get data
DATA="`curl -X GET -s -o - -H 'Content-Type: application/json; charset=utf-8' "http://localhost:8080/settings/get_settings"`"
echo "Final JSON: $DATA"
if [ $? != 0 ] ; then
    echo "curl ERROR" ; exit 1
fi








# reset orig settings
RESULT="`curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d $ORIGDATA 'http://localhost:8080/settings/set_settings'`"
if [ $? != 0 ] ; then
    echo "set_settings error"
    exit 1
fi
if echo $RESULT | grep -q OK ; then
    echo "Test pass"
else
    echo "Test FAIL"
fi




