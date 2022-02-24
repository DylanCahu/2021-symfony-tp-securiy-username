<?php

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

class SecurityControllerTest extends WebTestCase
{

    public function testShowLogin(): void
    {
        $client = static::createClient();

        $client->request('GET', '/login');

        //verifie que la page est envoyée
        $this->assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());

        //verifie que le title de la page est "Log In!"
        $this->assertSelectorTextContains('html head title', 'Log in!');

   
    }

    private function logIn($userName = 'user', $userRole = 'ROLE_USER')
    {
        $session = self::$container->get('session');


        $firewallName = 'main';
        // if you don't define multiple connected firewalls, the context defaults to the firewall name
        // See https://symfony.com/doc/current/reference/configuration/security.html#firewall-context
        $firewallContext = 'main';

        // you may need to use a different token class depending on your application.
        // for example, when using Guard authentication you must instantiate PostAuthenticationGuardToken
        $token = new UsernamePasswordToken('admin', null, $firewallName, ['ROLE_ADMIN']);
        $session->set('_security_'.$firewallContext, serialize($token));
        $session->save();

        $cookie = new Cookie($session->getName(), $session->getId());
        $this->client->getCookieJar()->set($cookie);
    }

    public function testSecureRoleUser()
    {
        $this->logIn('user', 'ROLE_USER');
        $crawler = $client->request('GET', '/category/');

        $this->assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());
       // $this->assertSame('Admin Dashboard', $crawler->filter('h1')->text());
    }
}
