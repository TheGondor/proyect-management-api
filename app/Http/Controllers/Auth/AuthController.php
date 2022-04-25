<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    public function login(Request $request)
    {
        $response = new \StdClass;

        $validate = Validator::make($request->all(),[
            'email' => 'required|string|email|exists:users,email',
            'password' => 'required|string',
        ]);
        $response->status = false;
        $response->message = $validate->errors();
        $code = 400;

        if(!$validate->fails()){
            $credentials = $request->only('email', 'password');

            $token = Auth::attempt($credentials);
            if (!$token) {
                $response->status = false;
                $response->message = 'Contraseña incorrecta';
                $code = 401;
            }
            else{
                $user = Auth::user();
                $response->status = true;
                $response->message = 'Autentificacion correcta';
                $response->user = $user;
                $response->token = $token;
                $code = 200;
            }

        }

        return response()->json($response, $code);

    }

    public function register(Request $request)
    {
        $response = new \StdClass;
        $response->status = true;
        $code = 200;
        $validate = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if(!$validate->fails()){
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            $token = Auth::login($user);
            $response->status = true;
            $response->user = $user;
            $response->message = "Usuario registrado correctamente";
            $response->token = $token;
        }
        else{
            $response->status = false;
            $response->message = $validate->errors();
            $code = 400;
        }
        return response()->json($response, $code);
    }

    public function logout(Request $request)
    {

        Auth::logout();
        // $token = $request->header( 'Authorization' );
        // JWTAuth::parseToken()->invalidate( $token );
        $response = new \StdClass;
        $response->status = true;
        $response->message = "Usuario desconectado correctamente";
        $code = 200;
        return response()->json($response, $code);
    }

    public function me()
    {
        $response = new \StdClass;
        if(Auth::check()){

            $response->status = true;
            $response->user = Auth::user();
            $code = 200;
        }
       else{
           $code = 400;
           $response->status = false;
       }
        return response()->json($response, $code);
    }

    public function refresh()
    {
        $response = new \StdClass;
        $response->status = true;
        $response->user = Auth::user();
        $token = Auth::refresh();
        $code = 200;
        return response()->json($response, $code);
    }

}
