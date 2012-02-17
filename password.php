<?php
/**
* Password Generation
*
* @phpver 5.0
* @author Robin Metcalfe <robin@solarisedesign.co.uk>
* @version 1.01
* @package strongPass
* Date     :  17th Feb 2012
* Purpose  :  Creating a strong password and hash value with salt
*/ 

/**
 * A password generation class
 * @package strongPass
 */
class StrongPass {

    //to store the salt we use in hash generation
    private $salt;
    //maximum size of the salt value
    private $salt_size = 30;
    
    //the length of the password to generate
    private $len;
    //to store the algorithm used to encrypt
    private $alg;
    //valid algorithms we are allowing
    private $valid_alg = array("md5", "sha1");
    
    //the results of the hash and password will be stored in these
    //publicly accessible variables
    public $hash;
    public $pass;
    
    
    
    function __construct($length = null, $custom_pass = "", $algorithm = "md5"){
        //initialise values
        $this->hash = "";
        //if the user wants to specify a custom password to hash
        $this->pass = ($custom_pass==null)?"":$custom_pass;
        $this->salt = "";
        //check that we're using either md5 or sha1
        $this->alg = (in_array($algorithm, $this->valid_alg))?$algorithm:"md5";
        //if we have specified a length, generate a password
        if($length !== null){
            $this->len = $length;
            $this->_makeSalt();
            $this->_generate();
        }
        //if a length hasn't been generated, we can just use this instance
        //of StrongPass to call confirm(); to check if a password/hash combo
        //is valid
    }
    
    /**
     * encrypts a string with the chosed encryption type in $this->alg
     * @access private
     * @param string $string
     * @return string $encrypted
     */
    private function _encrypt($string){
        //call the function defined by the chosen algorithm to
        //encrypt the data e.g. md5(), sha1()
        $encrypted = call_user_func($this->alg, $string);
        return $encrypted;
    }
    
    
    /**
     * Perform a string of reversible operations to encode/decode our
     * salt
     */
    private function _decode($string){
        return base64_decode(strrev(str_rot13($string)));
    }
    
    private function _encode($string){
        return str_rot13(strrev(base64_encode($string)));
    }
        
    /**
     * generates a value for $this->salt
     * @access private
     */
    private function _makeSalt(){
        //generate a random salt of 30 characters using mt_rand
        //as of PHP 4.1.0 mt_rand doesn't need to be seeded with
        //mt_srand, but we're doing that here, just to be sure
        //..ADD SALT thing
        $this->salt = substr($this->_encrypt(mt_rand()), 0, $this->salt_size);
    }

    /**
     * generate a random string of characters of length $length
     * @static
     * @access private
     * @params int $length
     * @return string $pass
     */    
    private static function _constructPassword($length){
        $symbols = "#@%&(=;[]+";
        $chars = "abcdfghjkmnpqrstvwxyz23456789ABCDFGHJKLMNPQRSTVWXYZ";
            
        //generate the password string
        $pass = "";

        for($i=0; $i<$length; $i++){
            $rand = rand() % strlen($chars.$symbols);
            $pass .= substr($chars.$symbols, $rand, 1);
        }
        return $pass;
    }
    
    /**
     * Public access for the static function _constructPassword
     * @static
     * @access private
     * @param int $length
     * @return string
     */
    public static function make($length){
        return self::_constructPassword($length);
    }
    
    /*
     * Generates the password/hash combination
     * @access private
     */
    private function _generate(){
        //length must be > 6 and <= 64
        if(!filter_var($this->len, FILTER_VALIDATE_INT, array("min_range" => 6, "max_range" => 64))){
            $this->len = 8;   
        }
            
        $this->pass = ($this->pass=="")?self::_constructPassword($this->len):$this->pass;
        
        $salt = $this->_encode($this->salt);
    
        $this->hash = $salt.$this->_encrypt($salt.$this->pass);
    }    

    /**
     * detects the algorithm used to encrypt the hash, md5 or sha1
     * @param string $hash
     * @access private
     */    
    private function _detectAlgorithm($hash){
        //based on the length of the hash, we can tell which algorithm
        //was used to produce it
        $len = strlen($hash);
        if($len == 32){
            $this->alg = "md5";   
        } else if($len == 40){
            $this->alg = "sha1";   
        }
    }
    
    /**
     * function used to determine if $hash == $pass
     * @access private
     * @param string $pass
     * @param string $hash
     * @return bool
     */
    private function _confirmPassword($pass, $hash){
        //create a blank temporary string of length $this->salt_size
        //to check what size our salt should be when base64_decode is called
        $tmp = "";
        for($i=0; $i<$this->salt_size; $i++){
            $tmp.="o";
        }
        //figure out how long our salt should be when encoded
        $encoded_salt_length = strlen($this->_encode($tmp));
        
        //find the salt string used by fetching
        //the first n=$salt_length characters of $hash
        //and decoding with $this->_decode
        $salt = $this->_decode(substr($hash, 0, $encoded_salt_length));
        
        //find the old hash, and the new one generated from our user password       
        
        // 1) Stored hash
        // - using the salt_length, we can return the remainder of the string
        //   which corresponds to our original hash
        $stored_hash = substr($hash, $encoded_salt_length);
        
        //find out if the hash is a md5 hash or an sha1 hash
        $this->_detectAlgorithm($stored_hash);
        
        // 2) New hash, built using the provided user password
        // - The hash has been encrypted using the base64_encoded value of $salt
        //   Here, we check that when we decode $salt and prepend it to our
        //   user supplied password $pass, then encrypt it, it matches
        //   the hash we have stored for this password/user
        $check_hash = $this->_encrypt($this->_encode($salt).$pass);
        
        //so if they match, then the password is correct
        if($check_hash === $stored_hash){
            return true;   
        } else {
            return false;
        }
    }
    
    /**
     * public access method for _confirmPassword()
     * @access public
     * @param string $pass
     * @param string $hash
     * @return string
     */
    public function confirm($pass, $hash){
        return $this->_confirmPassword($pass, $hash);
    }
}
?>