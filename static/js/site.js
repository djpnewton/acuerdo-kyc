// This file is not required for the greenID Simple UI.

function getRequiredFields() 
{
	var country = $('#usethiscountry').val();
	
	var townCityElement = document.getElementById("townCity");
	
	var requiredFieldsOneFitsAll = [ "givenNames", "surname", "streetNumber",
	           			"streetName", "suburb", "state", "postcode", "dob" ];
	
	var requiredFieldsWithNZTownCity = [ "givenNames", "surname", "streetNumber",
	    	           			"streetName", "townCity", "postcode", "dob" ];

	var requiredFieldsGB = [ "givenNames", "surname",
	                         "streetName", "town", "postcode", "dob" ];

	if (country === 'NZ' && townCityElement !== null)
	{
		return requiredFieldsWithNZTownCity;
	}
	else if (country === 'GB')
	{
		return requiredFieldsGB;
	}
	else
	{
		return requiredFieldsOneFitsAll;	
	}
}
function isGeneralInjection (value)
{
    return /^.*[=@<>|%]+.*/.test(value);
}


function isCSSInjection (value)
{
    return /^.*\/\/.*$/.test(value);
}

function isCSVInjection(value)
{
    return /^[+-=@<>|%].*$/.test(value) && value.length > 1;
}


function isNameValid(value) {

	var isValid = /^([^0-9]*)$/.test(value);

	if(injectionValidate(value))
	{
		isValid = false
	}
	return isValid
}

function injectionValidate(value){

	var isValid = false
	if(isGeneralInjection(value) || isCSSInjection(value) || isCSVInjection(value))
	{
		isValid = true
	}

	return  isValid
}


function validateDob(day, month, year) {
	
	if (month > 12) {
		return false;
	}

	if (day > 31) {
		return false;
	}

	var dob = new Date(year, month, day);

	if (Object.prototype.toString.call(dob) !== "[object Date]") {
		// it's not a date.
		return false;
	}

	if (isNaN(dob.getTime())) {
		return false;
	}

	// ..and in the past
	var now = new Date();
	if (dob > now) {
		return false;
	}

	return true;
}

function isDobValid(value) {
		
	var data = value.split("\/");

	if (data.length != 3) {
		return false;
	}

	if (countryIsUSA()) {
		return validateDob(data[1], data[0], data[2]);
	}

	return validateDob(data[0], data[1], data[2]);
}

function checkValidNames() {
	var nameFields = [ "givenNames", "middleNames", "surname", "streetName",
			"suburb" ];
	var allCool = true;

	$.each(nameFields, function(index, name) {
		if (!isNameValid($('#' + name).val())) {
			$("#" + name).parent().addClass("has-error");
			allCool = false;
		}
	});
	return allCool;

}

function checkValidDob() {
	var valid = isDobValid($("#dob").val());
	if (!valid) {
		$("#dob").parent().parent().addClass("has-error");
	}
	return valid;
}

function countryIsUSA() {
	
	var country = $('#usethiscountry').val();

	if (country) {
		if (country === "US") {
			return true;
		}
	}
	
	return false;
}

function clearErrors() {
	$(".has-error .help-block").remove();
	$(".has-error").removeClass("has-error");
}

function checkRequiredFields() {
	var allCool = true;
	
	$.each(getRequiredFields(), function(index, value) {
		if ($("#" + value).val() == "") {
			
			if ( $("#" + value).parent().hasClass("input-group") ) {
				var parentDiv = $("#" + value).parent().parent();
			} else {
				var parentDiv = $("#" + value).parent();
			}
			parentDiv.addClass("has-error").append("<span class=\"help-block\">This is a required field</span>");
			allCool = false;
		}
	})
	return allCool;
};

function checkZip() {
	
}

function checkSSN() {
	
	var ssn = $("#usSocialSecurityNumber").val();
	
	if (ssn === undefined || ssn === null || ssn == "") {
		return true;
	}
	
	if (ssn.match("^[0-9]{3}-[0-9]{2}-[0-9]{4}$")) {
		return true;
	}
	
	$("#usSocialSecurityNumber").parent().addClass("has-error").append("<span class=\"help-block\">Please enter a valid social security number</span>");
	return false;
}

function checkValidUSAAddress() {
	
	var zip = $("#postcode").val();
	
	if (zip === undefined || zip === null || zip == "") {
		return true;
	}
	
	if (zip.match("^[0-9]{5}$")) {
		return true;
	}
	
	$("#postcode").parent().addClass("has-error").append("<span class=\"help-block\">Please enter a 5 digit zip code</span>");
	return false;
}

// This function is an example of the kind of thing you might like to use as the preSubmitValidationCallback
// so that you can validate your form before greenID takes control. 
// If it returns false, greenID hands control back before registering the user so they can fix input errors.
function onValidation() {
	clearErrors();

	var allValidReq = checkRequiredFields();
	var allValidDob = true;
	if ($.inArray("dob", getRequiredFields()) > 0)
	{
		allValidDob = checkValidDob();
	}
	
	var allValidNames = checkValidNames();

	if ($("#usSocialSecurityNumber").length) {
		allValidNames = allValidNames && checkSSN();
	}
	
	var allValidAddress = true;
	if (countryIsUSA()) {
		allValidAddress = checkValidUSAAddress();
	}
	
	return allValidReq && allValidDob && allValidNames && allValidAddress;
};

function onRegister(verificationId, userData) {
	var verificationIdInput = document.getElementById("verificationId");
    verificationIdInput.value = verificationId;
	var verificationTokenInput = document.getElementById("verificationToken");
    verificationTokenInput.value = userData.verificationToken;
};

// Datepicker
// noConflict() is needed if jQuery UI is included in the page
var datepicker = $.fn.datepicker.noConflict();
$.fn.bootstrapDP = datepicker; 

$(".datepicker").click( function() {
	
	var format = "dd/mm/yyyy";

	if (countryIsUSA()) {
		format = "mm/dd/yyyy";
	}
				    	
	$('.input-group.date').bootstrapDP({
	    format: format,
	    autoclose: true,
	    startView: 2
	});

	$(this).parent().bootstrapDP('show');
	
})

function getEnvironment() {
	var host = window.location.host
		
	if (host === 'local.edentiti.com') {
		return 'local'
	}
	
	if (host === 'local.vixverify.com') {
		return 'local'
	}

	if (host === 'balpha.edentiti.com') {
		return 'sandbox'
	}
	
	if (host === 'balpha.vixverify.com') {
		return 'sandbox'
	}

	if (host === 'staging.vixverify.com') {
		return 'au-stag'
	}
	
	if (host === 'dev1.vixverify.com') {
		return 'au-dev1';
	}
	
	if (host === 'dev2.vixverify.com') {
		return 'au-dev2';
	}
	
	if (host === 'dev3.vixverify.com') {
		return 'au-dev3';
	}

	return 'test'
}

var greenidEnvironment = getEnvironment();
