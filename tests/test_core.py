from apiat.core.openapi import enumerate_endpoints

def test_openapi_enumeration():
    spec={'paths':{'/users/{id}':{'get':{'operationId':'getUser','parameters':[{'name':'id','in':'path'}]}}}}
    eps=enumerate_endpoints(spec)
    assert len(eps)==1
    assert eps[0].operation_id=='getUser'
    assert eps[0].method=='GET'
