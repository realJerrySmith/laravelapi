<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use App\Providers\RouteServiceProvider;
// use Illuminate\Foundation\Auth\VerifiesEmails;

class VerificationController extends Controller
{
  

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        // $this->middleware('signed')->only('verify');
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }

    public function verify(Request $request, User $user) // override these methods to taper them to our api needs
    {
        // chef if url is a valid signed url from laravel
        if(! URL::hasValidSignature($request)) {
            return response()->json(["errors" => [
                "message" => "Invalid verification link or signature"
            ]], 422);
        }

        // check if the user has already verified account
        if($user->hasVerifiedEmail()) {
            return response()->json(["errors" => [
                "message" => "Email adress already verified"
            ]], 422);
        }

        $user->markEmailAsVerified();
        event(new Verified($user));

        return response()->json(['message' => 'Email successfully verified', 200]);


    }

    public function resend(Request $request) // override these methods to taper them to our api needs
    {
        // validate that the request has the users email
        $this->validate($request, [
            'email' => ['email', 'required']
        ]);

        // grab user by email
        $user = User::where('email', $request->email)->first();
        if(! $user) {
            return response()->json(["errors" => [
                "email" => "No user could be found with this email adress"
            ]], 422);
        }

        // check if the user has already verified account
        if($user->hasVerifiedEmail()) {
            return response()->json(["errors" => [
                "message" => "Email adress already verified"
            ]], 422);
        }

        $user->sendEmailVerificationNotification();

        return response()->json(['status' => "verification link resent"]);
    }
    
}
