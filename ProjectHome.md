`MonkeyFist` is a dynamic request forgery attack tool that was released at Black Hat USA 2009. It allows you to easily pull of dynamic request forgeries using different scenarios such as redirects, pages, POST based attacks, and even fixation type attacks. This makes the tool useful for bypassing Cross-Site Request Forgery protection mechanisms.

## What Does It Do? ##
`MonkeyFist` is a tool that creates dynamic request forgeries based on cross-domain data leakage. The tool then constructs a payload based on data in the payloads.xml file and sends it to the user's browser. This may include session data bypassing protection mechanisms for Cross-Site Request Forgery.

## What is it written in? ##
It is written in Python which means it is cross platform. Many operating systems already come with Python installed. The only dependency as of now is that lxml http://codespeak.net/lxml/ be installed. Currently this is just being used for the fixation payload type.

## More Information ##
If you need more information on usage or practical examples you have a couple of options. You can check out the Neohaxor blog which will have updates from time to time. It is located at http://www.neohaxor.org More specifically I posted an intro to `MonkeyFist`  http://www.neohaxor.org/2009/08/12/monkeyfist-fu-the-intro/ as well as get an introduction to Dynamic Cross-Site Request Forgery attacks here.  http://www.neohaxor.org/2009/08/11/dynamic-cross-site-request-forgery/

## About ##
`MonkeyFist` (C) copyright Nathan Hamiel, 2010

Twitter: https://twitter.com/nathanhamiel