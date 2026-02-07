function age(bdate) {
    const prompt = require(prompt-sync)
    var date = new Date();
    var yearborn = new Date(bdate);

    var age = date.getFullYear() - yearborn.getFullYear();
    var month = date.getMonth() - yearborn.getMonth();
    console.log(age)

}



var bdate = prompt('enter your dob:') ;
age(bdate)
