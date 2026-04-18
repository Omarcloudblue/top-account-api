TopAccountService.AccountResult result = TopAccountService.createAccount(
    'TestEmailUser2',
    'pass1234',
    'omarmarmolejo0826@gmail.com'
);
System.debug('SUCCESS: ' + result.success);
System.debug('MESSAGE: ' + result.message);
