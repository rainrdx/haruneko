﻿import { TestFixture } from '../../../test/WebsitesFixture';

const config = {
    plugin: {
        id: 'traduccionesmoonlight',
        title: 'Traducciones Moonlight'
    },
    container: {
        url: 'https://traduccionesmoonlight.com/manga/sacrificio-humano/',
        id: '/manga/sacrificio-humano/',
        title: 'SACRIFICIO HUMANO'
    },
    child: {
        id: '/sacrificio-humano-volumen-1/',
        title: 'Capítulo 1'
    },
    entry: {
        index: 0,
        size: 4_442_029,
        type: 'image/png'
    }
};

new TestFixture(config).AssertWebsite();