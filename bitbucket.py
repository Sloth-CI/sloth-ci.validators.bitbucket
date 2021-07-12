def validate(request, validation_data):
    """Check payload from Bitbucket: the origin IP must be genuine; the repo owner and title must be valid.

    :param request: `CherryPy request <http://docs.cherrypy.org/en/latest/pkg/cherrypy.html#cherrypy._cprequest.Request>`_ instance representing incoming request
    :param validation_data: dict with the keys ``owner``, ``repo``, and ``branches``, parsed from the config

    :returns: namedtuple(status, message, list of extracted params as dicts), e.g. ``Response(status=200, message='Payload validated. Branches: default', [{'branch': 'default'}])``
    """

    from collections import namedtuple

    from ipaddress import ip_address, ip_network


    response = namedtuple('Response', ('status', 'message', 'param_dicts'))

    if request.method != 'POST':
        return response(405, 'Payload validation failed: Wrong method, POST expected, got %s.' % request.method, [])

    trusted_ip_ranges = ('104.192.143.192/28', '104.192.143.208/28')

    trusted_ips = (ip_network(ip_range) for ip_range in trusted_ip_ranges)

    remote_ip = ip_address(request.remote.ip)

    if not any(remote_ip in ip_range for ip_range in trusted_ips):
        return response(403, 'Payload validation failed: Unverified remote IP: %s.' % remote_ip, [])

    try:
        payload = request.json

        owner, repo = payload['repository']['full_name'].split('/')

        if owner != validation_data['owner']:
            return response(403, 'Payload validation failed: wrong owner: %s' % owner, [])

        if repo != validation_data['repo']:
            return response(403, 'Payload validation failed: wrong repository: %s' % repo, [])

        branches = {change['new']['name'] for change in payload['push']['changes']}

        allowed_branches = set(validation_data.get('branches', branches))

        if not branches & allowed_branches:
            return response(403, 'Payload validation failed: wrong branches: %s' % branches, [])

        param_dicts = [{'branch': branch} for branch in branches & allowed_branches]

        return response(200, 'Payload validated. Branches: %s' % ', '.join(branches), param_dicts)

    except Exception as e:
        return response(400, 'Payload validation failed: %s' % e, [])
