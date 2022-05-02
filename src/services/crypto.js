const Pinblock = require('pinblock');
const des3 = require('node-cardcrypto').des;

class CryptoService {
  constructor(settings, log){
    this.settings = settings;
    this.log = log;
    this.pinblock = new Pinblock();
  
    this.keys = {
      master_key: {
        key: '', 
        check_value: ''
	  },
      comms_key: {
        key: '', 
        check_value: ''
	  },
      mac_key: {
        key: '', 
        check_value: ''
	  }
    };

    (settings.get('master_key')) ? this.setMasterKey(settings.get('master_key')) : this.setMasterKey('');
    (settings.get('comms_key')) ? this.setCommsKey(settings.get('comms_key')) : this.setCommsKey('');
  }

  /**
   * [dec2hex convert decimal string to hex string, e.g. 040198145193087203201076202216192211251240251237 to 28C691C157CBC94CCAD8C0D3FBF0FBED]
   * @param  {[type]} dec_string [decimal string ]
   * @return {[type]}            [hex string]
   */
  dec2hex(dec_string){
    let hex_string = '';
    for(let i = 0; i < dec_string.length; i += 3){
      let chunk = parseInt(dec_string.substr(i, 3), 10).toString(16);
      (chunk.length === 1) ? (hex_string = hex_string + '0' + chunk ) : hex_string += chunk;
    }

    return hex_string.toUpperCase();
  }

  /**
   * [decryptWithMasterKey description]
   * @param {[type]} key_decimal [description]
   * @param {[type]} length      [description]
   */
  decryptWithMasterKey(key_decimal, length) {
    let key = this.dec2hex(key_decimal);
    let expected_key_length = parseInt(length, 16) / 1.5;

    if(key.length !== expected_key_length){
      this.log.error('Key length mismatch. New key has length ' + key.length + ', but expected length is ' + expected_key_length);
      return null;
    }

    this.log.info('key received: ' + key);
	this.keys.master_key.key = settings.get('master_key');
    if(!this.keys.master_key.key){
      this.log.error('Invalid master key: ' + this.keys.master_key.key);
      return null;
    }

    let decryptedMACKey = des3.ecb_decrypt(this.keys.master_key.key, key);
    this.log.info('key value: ' + decryptedMACKey);
	return decryptedMACKey;
  }

  /**
   * [setCommsKey description]
   * @param {[type]} key [description]
   */
  setCommsKey(key){
    this.keys.comms_key.key = key;
    this.log.info('New comms key value: ' + this.keys.comms_key.key);
    this.settings.set('comms_key', this.keys.comms_key.key);
    return true;
  }

  /**
   * [setMasterKey description]
   * @param {[type]} key [description]
   */
  setMasterKey(key){
    this.keys.master_key.key = key;
    this.log.info('New master key value: ' + this.keys.comms_key.key);
    this.settings.set('master_key', key);
  }

  /**
   * [setMACKey description]
   * @param {[type]} key [description]
   */
  setMACKey(key)
  {
    this.keys.mac_key.key = key;
    this.log.info('New MAC key value: ' + this.keys.mac_key.key);
    this.settings.set('mac_key', this.keys.mac_key.key);
    return true;
  }

  /**
   * [getKeyCheckValue description]
   * @param  {[type]} key [description]
   * @return {[type]}     [description]
   */
  getKeyCheckValue(key){
    let kcv = des3.ecb_encrypt(key, '00000000000000000000000000000000');
    if(kcv)
      return kcv.substr(0, 6);
    else
      return null;
  }

  /**
   * [getCommsKey description]
   * @return {[type]} [description]
   */
  getCommsKey()
  {
	this.keys.comms_key.key = settings.get('comms_key')
    return [this.keys.comms_key.key, this.getKeyCheckValue(this.keys.comms_key.key)];
  }

  /**
   * [getMasterKey description]
   * @return {[type]} [description]
   */
  getMasterKey()
  {
	this.keys.master_key.key = settings.get('master_key')
    return [this.keys.master_key.key, this.getKeyCheckValue(this.keys.master_key.key)] ;
  }

  /**
   * [getMACKey description]
   * @return {[type]} [description]
   */
  getMACKey()
  {
	this.keys.mac_key.key = settings.get('mac_key')
    return [this.keys.mac_key.key, this.getKeyCheckValue(this.keys.mac_key.key)] ;
  }


  getKey(type)
  {
    switch(type)
	{
      case 'master':
        return this.getMasterKey();

      case 'comms':
        return this.getCommsKey();

      case 'mac':
        return this.getMACKey();
    }
  }

  /**
   * [getEncryptedPIN description]
   * @return {[type]}           [description]
   */
  getEncryptedPIN(PIN_buffer, card_number)
  {
    this.log.info('JFRD services\\crypto.js line 129');
    if(this.keys.comms_key.key)
	{
      this.log.info('JFRD services\crypto.js line 132');
	  let pinblock = this.pinblock.get(PIN_buffer, card_number);
      this.log.info('Clear PIN block:     [' + pinblock + ']');
      this.log.info('JFRD services\crypto.js line 135 comms_key >' + this.keys.comms_key.key + '<');

      let encrypted_pinblock = des3.ecb_encrypt(this.keys.comms_key.key, pinblock);
      this.log.info('Encrypted PIN block: [' + encrypted_pinblock + ']');

      let atm_pinblock = this.pinblock.encode_to_atm_format(encrypted_pinblock);
      this.log.info('Formatted PIN block: [' + atm_pinblock + ']');
      
      return atm_pinblock;
    } 
	else 
	{
      this.log.info('JFRD services\crypto.js line 145');
      this.log.error('Terminal key is not set, unable to encrypt PIN block');
      return null;
    }
  }

  format(data){
    let formatted = '';
    for(let i = 0; i < data.length; i++){
      if(i !== 0 && i % 4 === 0)
        formatted += ' ';
      formatted += data[i];
    }
    return formatted;
  }
}

module.exports = CryptoService;
