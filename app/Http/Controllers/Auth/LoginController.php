<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Validation\ValidationException;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class LoginController extends Controller
{

    use AuthenticatesUsers;

    public function attemptLogin(Request $request)
    {
        // attempt to issue a token to the user based on the login credentials
        $token = $this->guard()->attempt($this->credentials($request)); // $requests hold email and password

        if( ! $token){
            return false;
        }

        // get the authenticated user; at this point we already authenticated that the user exits 
        $user = $this->guard()->user();

        if($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()){ // if the user is supposed to verify their email and has not done so we return false
            return false;
        }

        // set the users token
        $this->guard()->setToken($token);

        return true;
    }

    protected function sendLoginResponse(Request $request)
    {
        $this->clearLoginAttempts($request); // clear any login attempts that the user might have made

        // get the token from the authentication guard (jwt here)
        // cast token to string because we are sending it to the ui
        $token = (string)$this->guard()->getToken();

        // extract the expiry date of the token; we use this in the ui to set cookies with an expiry date
        $expiration = $this->guard()->getPayload()->get('exp');

        return response()->json([
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $expiration
        ]);

    }

    // for example when the user needs to verify their email but they havent
    protected function sendFailedLoginResponse()
    {
        $user = $this->guard()->user();

        if($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()){
            return response()->json(["errors" => [
                "verification" => "You need to verify your email account"
            ]]);
        }

        throw ValidationException::withMessages([
            $this->username() => "Authentication failed, invalid credentials"
        ]);
    }

    public function logout()
    {
        $this->guard()->logout();

        return response()->json(['message' => 'Logged out successfully']);
    }
    
}
